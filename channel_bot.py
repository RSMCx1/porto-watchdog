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

try:
    import pymumble_py3 as pymumble
    from pymumble_py3.messages import MoveCmd
except ImportError:
    print("ERROR: pymumble not found. Install with: pip install pymumble")
    sys.exit(1)

log = logging.getLogger('channel-bot')

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
def verify_packet(data, secret):
    """Verify and parse a signed packet.
    Returns (command, radio_id) or (None, None) on failure.
    """
    if len(data) != PKT_SIZE:
        log.debug("Bad packet size: %d", len(data))
        return None, None

    payload = data[:PAYLOAD_LEN]
    received_hmac = data[HMAC_OFFSET:HMAC_OFFSET + HMAC_LEN]

    expected_hmac = hmac.new(
        secret.encode('utf-8'),
        payload,
        hashlib.sha256
    ).digest()

    if not hmac.compare_digest(received_hmac, expected_hmac):
        log.warning("HMAC verification failed - invalid secret or tampered packet")
        return None, None

    cmd = chr(data[0])
    radio_id = data[1:1 + RADIO_ID_LEN].rstrip(b'\x00').decode('ascii', errors='replace')
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
                 skip_root=True, wrap_around=True):
        """
        radio_map: dict mapping radio_id -> mumla_username (supports fnmatch wildcards)
        e.g. {'radio01': 'TE300K', 'radio02': 'P*'}
        """
        self.mumble = mumble_obj
        self.radio_map = radio_map
        self.sort_by = sort_by
        self.skip_root = skip_root
        self.wrap_around = wrap_around

    def get_sorted_channels(self):
        channels = list(self.mumble.channels.values())
        if self.skip_root:
            channels = [c for c in channels if c['channel_id'] != 0]
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
        self.secret = config['secret']
        self.allowed_ips = set()

        if config['allowed_ips'].strip():
            self.allowed_ips = set(
                ip.strip() for ip in config['allowed_ips'].split(',')
            )

    def connect_mumble(self):
        host = self.config['mumble_host']
        port = self.config['mumble_port']
        username = self.config['bot_username']
        password = self.config['bot_password']

        log.info("Connecting to %s:%d as '%s'...", host, port, username)
        self.mumble = pymumble.Mumble(
            host, username, port=port, password=password, reconnect=True
        )
        self.mumble.set_receive_sound(False)
        self.mumble.start()
        self.mumble.is_ready()
        log.info("Connected!")

        self.channel_mgr = ChannelManager(
            self.mumble, self.radio_map,
            sort_by=self.config['channels_sort_by'],
            skip_root=self.config['channels_skip_root'],
            wrap_around=self.config['channels_wrap_around'],
        )

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

        cmd, radio_id = verify_packet(data, self.secret)
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
            msg = self.config['emergency_format']
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
        log.info("Channels (%d):", len(channels))
        for ch in channels:
            log.info("  [%d] %s", ch['channel_id'], ch['name'])

        log.info("Radio -> User mapping:")
        for rid, uname in self.radio_map.items():
            user = self.channel_mgr.find_user_by_name(uname)
            if user:
                status = f"channel {user['channel_id']}"
                display = f"{uname} -> {user['name']}" if uname != user['name'] else uname
            else:
                status = "NOT CONNECTED"
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
        'bot_password': os.environ.get('BOT_PASSWORD', ''),
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
    }

    # Parse RADIOS: "radio01=TE300K,radio02=P*"
    # Supports fnmatch wildcards in usernames (e.g. P* matches any user starting with P)
    config['radios'] = {}
    radios_str = os.environ.get('RADIOS', '')
    if radios_str.strip():
        for pair in radios_str.split(','):
            pair = pair.strip()
            if '=' in pair:
                radio_id, mumla_user = pair.split('=', 1)
                config['radios'][radio_id.strip()] = mumla_user.strip()

    return config


def main():
    import argparse
    p = argparse.ArgumentParser(description='Mumla Channel Bot - Multi-radio')
    p.add_argument('--list', action='store_true',
                   help='List channels/users and exit')
    p.add_argument('--gen-secret', action='store_true',
                   help='Generate a random secret and exit')
    args = p.parse_args()

    if args.gen_secret:
        import secrets
        s = secrets.token_urlsafe(32)
        print(f"Generated secret: {s}")
        print("Set this as SECRET env var in docker-compose.yml")
        print("and in each radio's knob.conf secret=")
        return

    config = load_env_config()

    level = getattr(logging, config['log_level'].upper(), logging.INFO)
    logging.basicConfig(
        level=level,
        format='%(asctime)s [%(levelname)s] %(message)s'
    )

    if not config['secret']:
        log.error("No SECRET env var set! Run with --gen-secret to create one.")
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
