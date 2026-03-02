#!/usr/bin/env python3
"""
Mumla Channel Bot - Secure multi-radio channel switching for Mumble
=====================================================================
Receives HMAC-signed UDP from knob_reader binaries on multiple TE300K
radios and moves each radio's Mumla user between channels.

Supports emergency alerts (E) and ident broadcasts (I).
Announces via Mumble text message -> Mumla TTS.

All configuration via environment variables (see docker-compose.yml).

License: GPLv3
"""

import sys
import os
import hmac
import hashlib
import struct
import time
import signal
import logging
import socket
import fnmatch

pymumble = None
MoveCmd = None


def _load_pymumble():
    global pymumble, MoveCmd
    if pymumble is not None:
        return
    try:
        import pymumble_py3
        from pymumble_py3.messages import MoveCmd as _MoveCmd
        pymumble = pymumble_py3
        MoveCmd = _MoveCmd
    except ImportError:
        print("ERROR: pymumble not found. Install with: pip install pymumble")
        sys.exit(1)

log = logging.getLogger('porto-watchdog')

# Packet layout (must match knob_reader.c)
PKT_SIZE = 45
RADIO_ID_LEN = 8
PAYLOAD_LEN = 13   # cmd(1) + radio_id(8) + timestamp(4)
HMAC_OFFSET = 13
HMAC_LEN = 32

# Replay window: reject packets older than this (seconds)
REPLAY_WINDOW = 30

VALID_COMMANDS = ('N', 'P', 'E', 'I')


# ============================================================================
# Packet verification
# ============================================================================
def get_secret_for_radio(config, radio_id):
    """Return the secret for a given radio_id.
    Per-radio SECRETS take precedence over global SECRET.
    """
    if config['secrets'].get(radio_id):
        return config['secrets'][radio_id]
    if config['secret']:
        return config['secret']
    return None


def verify_packet(data, config):
    """Verify and parse a signed packet.
    Returns (command, radio_id) or (None, None) on failure.
    """
    if len(data) != PKT_SIZE:
        log.debug("Bad packet size: %d", len(data))
        return None, None

    # Extract radio_id before HMAC check (used only as key lookup)
    radio_id = data[1:1 + RADIO_ID_LEN].rstrip(b'\x00').decode('ascii', errors='replace')

    secret = get_secret_for_radio(config, radio_id)
    if secret is None:
        log.warning("No secret configured for radio '%s'", radio_id)
        return None, None

    payload = data[:PAYLOAD_LEN]
    received_hmac = data[HMAC_OFFSET:HMAC_OFFSET + HMAC_LEN]

    expected_hmac = hmac.new(
        secret.encode('utf-8'),
        payload,
        hashlib.sha256
    ).digest()

    if not hmac.compare_digest(received_hmac, expected_hmac):
        log.warning("HMAC verification failed (radio=%s)", radio_id)
        return None, None

    cmd = chr(data[0])
    timestamp = struct.unpack('>I', data[9:13])[0]

    now = int(time.time())
    age = abs(now - timestamp)
    if age > REPLAY_WINDOW:
        log.warning("Replay rejected: packet age %ds (radio=%s)", age, radio_id)
        return None, None

    if cmd not in VALID_COMMANDS:
        log.debug("Unknown command: %r", cmd)
        return None, None

    return cmd, radio_id


# ============================================================================
# Channel Manager (handles multiple radios)
# ============================================================================
class ChannelManager:
    def __init__(self, mumble_obj, radio_map, sort_by='id',
                 skip_root=True, wrap_around=True, skip_channels=None):
        """
        radio_map: dict mapping radio_id -> mumla_username (supports fnmatch wildcards)
        e.g. {'radio01': 'TE300K', 'radio02': 'P*'}
        skip_channels: set of channel names to exclude from rotation
        """
        self.mumble = mumble_obj
        self.radio_map = radio_map
        self.sort_by = sort_by
        self.skip_root = skip_root
        self.wrap_around = wrap_around
        self.skip_channels = skip_channels or set()

    def get_sorted_channels(self):
        channels = list(self.mumble.channels.values())
        if self.skip_root:
            channels = [c for c in channels if c['channel_id'] != 0]
        if self.skip_channels:
            channels = [c for c in channels
                        if c['name'] not in self.skip_channels]
        if self.sort_by == 'name':
            channels.sort(key=lambda c: c['name'].lower())
        else:
            channels.sort(key=lambda c: c['channel_id'])
        return channels

    def find_user_by_name(self, username):
        """Find a user by name. Supports fnmatch wildcards (e.g. 'P*')."""
        has_wildcard = '*' in username or '?' in username
        for session_id, user in self.mumble.users.items():
            if has_wildcard:
                if fnmatch.fnmatch(user['name'], username):
                    return user
            else:
                if user['name'] == username:
                    return user
        return None

    def switch(self, radio_id, direction):
        """Switch channel for a specific radio.
        Returns (channel_name, channel_id) or (None, None).
        """
        if radio_id not in self.radio_map:
            log.warning("Unknown radio_id: '%s'", radio_id)
            return None, None

        username = self.radio_map[radio_id]
        user = self.find_user_by_name(username)
        if not user:
            log.warning("User '%s' (radio %s) not found on server",
                        username, radio_id)
            return None, None

        channels = self.get_sorted_channels()
        if not channels:
            return None, None

        current_id = user['channel_id']
        current_idx = -1
        for i, ch in enumerate(channels):
            if ch['channel_id'] == current_id:
                current_idx = i
                break

        if current_idx == -1:
            new_idx = 0
        elif direction == 'next':
            new_idx = current_idx + 1
            if new_idx >= len(channels):
                new_idx = 0 if self.wrap_around else current_idx
        elif direction == 'prev':
            new_idx = current_idx - 1
            if new_idx < 0:
                new_idx = len(channels) - 1 if self.wrap_around else 0
        else:
            return None, None

        target = channels[new_idx]
        target_id = target['channel_id']
        target_name = target['name']

        if target_id == current_id:
            return target_name, target_id

        log.info("[%s] Moving '%s' -> %s (ID %d)",
                 radio_id, user['name'], target_name, target_id)
        try:
            cmd = MoveCmd(user['session'], target_id)
            self.mumble.execute_command(cmd)
        except Exception as e:
            log.error("Move failed: %s", e)
            return None, None

        return target_name, target_id


# ============================================================================
# Main Bot
# ============================================================================
class ChannelBot:
    def __init__(self, config):
        self.config = config
        self.running = False
        self.mumble = None
        self.channel_mgr = None
        self.last_switch = {}  # per-radio debounce
        self.debounce_ms = 200

        self.radio_map = config['radios']
        self.allowed_ips = set()

        if config['allowed_ips'].strip():
            self.allowed_ips = set(
                ip.strip() for ip in config['allowed_ips'].split(',')
            )

    def ensure_certificate(self):
        """Generate a persistent certificate so the bot can be registered."""
        cert_dir = self.config['cert_dir']
        certfile = os.path.join(cert_dir, 'bot.pem')
        keyfile = os.path.join(cert_dir, 'bot.key')
        if os.path.exists(certfile) and os.path.exists(keyfile):
            log.info("Using existing certificate: %s", certfile)
            return certfile, keyfile
        os.makedirs(cert_dir, exist_ok=True)
        log.info("Generating bot certificate in %s ...", cert_dir)
        import subprocess
        subprocess.run([
            'openssl', 'req', '-x509', '-newkey', 'rsa:2048',
            '-keyout', keyfile, '-out', certfile,
            '-days', '3650', '-nodes',
            '-subj', '/CN=' + self.config['bot_username'],
        ], check=True, capture_output=True)
        log.info("Certificate generated (valid 10 years)")
        return certfile, keyfile

    def connect_mumble(self):
        _load_pymumble()
        host = self.config['mumble_host']
        port = self.config['mumble_port']
        username = self.config['bot_username']
        password = self.config['mumble_server_password']
        certfile, keyfile = self.ensure_certificate()

        log.info("Connecting to %s:%d as '%s'...", host, port, username)
        self.mumble = pymumble.Mumble(
            host, username, port=port, password=password, reconnect=True,
            certfile=certfile, keyfile=keyfile,
        )
        self.mumble.set_receive_sound(False)
        self.mumble.start()
        self.mumble.is_ready()
        log.info("Connected!")

        # Register user-connected callback AFTER is_ready() so it doesn't
        # fire for every existing user during the initial sync handshake.
        if self.config['connect_message_enabled']:
            self.mumble.callbacks.set_callback(
                pymumble.constants.PYMUMBLE_CLBK_USERCREATED,
                self.on_user_connected,
            )

        self.channel_mgr = ChannelManager(
            self.mumble, self.radio_map,
            sort_by=self.config['channels_sort_by'],
            skip_root=self.config['channels_skip_root'],
            wrap_around=self.config['channels_wrap_around'],
            skip_channels=self.config['channels_skip'],
        )

    def on_user_connected(self, user):
        """Called when any user joins the server. Greet mapped radio users."""
        if not self.channel_mgr:
            return
        try:
            username = user['name']
            # Ignore the bot itself
            if username == self.config['bot_username']:
                return
            for radio_id, pattern in self.radio_map.items():
                if fnmatch.fnmatch(username, pattern) or username == pattern:
                    channel_id = user.get('channel_id', 0)
                    channel = self.mumble.channels.get(channel_id)
                    channel_name = channel['name'] if channel else 'unknown'
                    fmt = self.config['connect_message_format']
                    msg = fmt.format(
                        username=username,
                        channel=channel_name,
                    )
                    log.info("[%s] Radio connected: %s", radio_id, msg)
                    self.mumble.users[user['session']].send_text_message(msg)
                    break
        except Exception as e:
            log.warning("Failed to send connect message: %s", e)

    def announce(self, radio_id, channel_name, channel_id):
        """Send channel name to the radio user via text message (TTS)."""
        if not self.config['announce_enabled']:
            return
        username = self.radio_map.get(radio_id)
        if not username:
            return
        user = self.channel_mgr.find_user_by_name(username)
        if not user:
            return
        fmt = self.config['announce_format']
        msg = fmt.format(channel=channel_name, id=channel_id)
        try:
            self.mumble.users[user['session']].send_text_message(msg)
        except Exception as e:
            log.warning("Failed to send TTS message: %s", e)

    def broadcast_to_channel(self, radio_id, message):
        """Send a text message to the channel the radio user is in."""
        if radio_id not in self.radio_map:
            log.warning("broadcast: unknown radio_id '%s'", radio_id)
            return

        username = self.radio_map[radio_id]
        user = self.channel_mgr.find_user_by_name(username)
        if not user:
            log.warning("broadcast: user '%s' (radio %s) not on server",
                        username, radio_id)
            return

        channel_id = user['channel_id']
        try:
            self.mumble.channels[channel_id].send_text_message(message)
            log.info("[%s] Broadcast to channel %d: %s",
                     radio_id, channel_id, message)
        except Exception as e:
            log.error("broadcast failed: %s", e)

    def handle_packet(self, data, addr):
        # IP allowlist
        if self.allowed_ips and addr[0] not in self.allowed_ips:
            log.warning("Rejected packet from non-allowed IP: %s", addr[0])
            return

        cmd, radio_id = verify_packet(data, self.config)
        if cmd is None:
            return

        # Per-radio debounce
        now = time.time() * 1000
        last = self.last_switch.get(radio_id, 0)
        if now - last < self.debounce_ms:
            return
        self.last_switch[radio_id] = now

        if cmd in ('N', 'P'):
            direction = 'next' if cmd == 'N' else 'prev'
            name, cid = self.channel_mgr.switch(radio_id, direction)
            if name:
                self.announce(radio_id, name, cid)
        elif cmd == 'E':
            fmt = self.config['emergency_format']
            username = self.radio_map.get(radio_id, radio_id)
            user = self.channel_mgr.find_user_by_name(username)
            actual_name = user['name'] if user else username
            msg = fmt.format(username=actual_name)
            log.warning("[%s] EMERGENCY triggered", radio_id)
            self.broadcast_to_channel(radio_id, msg)
        elif cmd == 'I':
            fmt = self.config['ident_format']
            username = self.radio_map.get(radio_id, radio_id)
            # Resolve wildcard to actual connected username
            user = self.channel_mgr.find_user_by_name(username)
            actual_name = user['name'] if user else username
            msg = fmt.format(username=actual_name)
            self.broadcast_to_channel(radio_id, msg)

    def run(self):
        self.running = True
        self.connect_mumble()
        time.sleep(1)

        # Log setup
        channels = self.channel_mgr.get_sorted_channels()
        if self.config['channels_skip']:
            log.info("Skipping channels: %s",
                     ', '.join(sorted(self.config['channels_skip'])))
        log.info("Channels (%d):", len(channels))
        for ch in channels:
            log.info("  [%d] %s", ch['channel_id'], ch['name'])

        log.info("Radio -> User mapping:")
        for rid, uname in self.radio_map.items():
            user = self.channel_mgr.find_user_by_name(uname)
            key_type = "own key" if rid in self.config['secrets'] else "shared key"
            if user:
                status = f"channel {user['channel_id']}, {key_type}"
                display = f"{uname} -> {user['name']}" if uname != user['name'] else uname
            else:
                status = f"NOT CONNECTED, {key_type}"
                display = uname
            log.info("  %s -> %s (%s)", rid, display, status)

        if self.allowed_ips:
            log.info("Allowed source IPs: %s", ', '.join(self.allowed_ips))
        else:
            log.info("Accepting from any IP (use ALLOWED_IPS to restrict)")

        # UDP listener
        listen_addr = self.config['udp_addr']
        listen_port = self.config['udp_port']
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((listen_addr, listen_port))
        sock.settimeout(1.0)

        log.info("Listening on UDP %s:%d (HMAC-SHA256, replay window=%ds)",
                 listen_addr, listen_port, REPLAY_WINDOW)
        log.info("Commands: N(ext) P(rev) E(mergency) I(dent)")
        log.info("Ready!")

        try:
            while self.running:
                try:
                    data, addr = sock.recvfrom(128)
                except socket.timeout:
                    continue
                self.handle_packet(data, addr)
        except KeyboardInterrupt:
            pass
        finally:
            sock.close()
            if self.mumble:
                self.mumble.stop()
            log.info("Stopped.")

    def stop(self):
        self.running = False


# ============================================================================
# Config from environment variables
# ============================================================================
def load_env_config():
    """Load all configuration from environment variables."""

    def env_bool(key, default='true'):
        return os.environ.get(key, default).lower() in ('true', '1', 'yes')

    config = {
        'mumble_host': os.environ.get('MUMBLE_HOST', '127.0.0.1'),
        'mumble_port': int(os.environ.get('MUMBLE_PORT', '64738')),
        'bot_username': os.environ.get('BOT_USERNAME', 'ChannelBot'),
        'mumble_server_password': os.environ.get('MUMBLE_SERVER_PASSWORD', ''),
        'secret': os.environ.get('SECRET', ''),
        'allowed_ips': os.environ.get('ALLOWED_IPS', ''),
        'udp_port': int(os.environ.get('UDP_PORT', '4378')),
        'udp_addr': os.environ.get('UDP_ADDR', '0.0.0.0'),
        'channels_sort_by': os.environ.get('CHANNELS_SORT_BY', 'id'),
        'channels_skip_root': env_bool('CHANNELS_SKIP_ROOT', 'true'),
        'channels_wrap_around': env_bool('CHANNELS_WRAP_AROUND', 'true'),
        'announce_enabled': env_bool('ANNOUNCE_ENABLED', 'true'),
        'announce_format': os.environ.get('ANNOUNCE_FORMAT', '{channel}'),
        'log_level': os.environ.get('LOG_LEVEL', 'INFO'),
        'emergency_format': os.environ.get('EMERGENCY_FORMAT', 'alert alert'),
        'ident_format': os.environ.get('IDENT_FORMAT', '{username}'),
        'connect_message_enabled': env_bool('CONNECT_MESSAGE_ENABLED', 'true'),
        'connect_message_format': os.environ.get(
            'CONNECT_MESSAGE_FORMAT', '{username} {channel} connected'),
        'cert_dir': os.environ.get('CERT_DIR', '/app/certs'),
    }

    # Parse CHANNELS_SKIP: "Lobby,AFK,Admin" (comma-separated channel names to exclude)
    config['channels_skip'] = set()
    skip_str = os.environ.get('CHANNELS_SKIP', '')
    if skip_str.strip():
        config['channels_skip'] = set(
            name.strip() for name in skip_str.split(',') if name.strip()
        )

    # Parse RADIOS: "radio01=TE300K,radio02=P*"
    config['radios'] = {}
    radios_str = os.environ.get('RADIOS', '')
    if radios_str.strip():
        for pair in radios_str.split(','):
            pair = pair.strip()
            if '=' in pair:
                radio_id, mumla_user = pair.split('=', 1)
                config['radios'][radio_id.strip()] = mumla_user.strip()

    # Parse SECRETS: "radio01=secretA,radio02=secretB" (per-radio keys)
    # Per-radio secrets take precedence over global SECRET fallback
    config['secrets'] = {}
    secrets_str = os.environ.get('SECRETS', '')
    if secrets_str.strip():
        for pair in secrets_str.split(','):
            pair = pair.strip()
            if '=' in pair:
                radio_id, secret = pair.split('=', 1)
                config['secrets'][radio_id.strip()] = secret.strip()

    return config


def main():
    import argparse
    p = argparse.ArgumentParser(description='Porto Watchdog - remote radio control')
    p.add_argument('--list', action='store_true',
                   help='List channels/users and exit')
    p.add_argument('--gen-secret', action='store_true',
                   help='Generate a random secret and exit')
    args = p.parse_args()

    if args.gen_secret:
        import secrets
        s = secrets.token_urlsafe(32)
        print(f"Generated secret: {s}")
        print()
        print("Option A - shared secret (all radios use the same key):")
        print(f"  SECRET=\"{s}\"")
        print()
        print("Option B - per-radio secrets (generate one per radio):")
        print(f"  SECRETS=\"radio01={s}\"")
        print("  Run --gen-secret again for each additional radio.")
        print()
        print("Set in docker-compose.yml and in each radio's knob.conf secret=")
        return

    config = load_env_config()

    level = getattr(logging, config['log_level'].upper(), logging.INFO)
    logging.basicConfig(
        level=level,
        format='%(asctime)s [%(levelname)s] %(message)s'
    )

    if not config['secret'] and not config['secrets']:
        log.error("No SECRET or SECRETS env var set! Run with --gen-secret to create one.")
        sys.exit(1)

    if not config['radios']:
        log.error("No RADIOS env var set! "
                  "Format: RADIOS=radio01=TE300K,radio02=P*")
        sys.exit(1)

    if args.list:
        bot = ChannelBot(config)
        bot.connect_mumble()
        time.sleep(1)
        print("\nChannels:")
        for ch_id, ch in sorted(bot.mumble.channels.items()):
            print(f"  [{ch_id}] {ch['name']}")
        print("\nUsers:")
        for sess, user in bot.mumble.users.items():
            print(f"  {user['name']} (session {sess}, "
                  f"channel {user['channel_id']})")
        bot.mumble.stop()
        return

    bot = ChannelBot(config)
    signal.signal(signal.SIGTERM, lambda s, f: bot.stop())
    signal.signal(signal.SIGINT, lambda s, f: bot.stop())
    bot.run()


if __name__ == '__main__':
    main()
