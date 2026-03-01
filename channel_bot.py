#!/usr/bin/env python3
"""
Mumla Channel Bot - Secure multi-radio channel switching for Mumble
=====================================================================
Receives HMAC-signed UDP from knob_reader binaries on multiple TE300K
radios and moves each radio's Mumla user between channels.

Announces via Mumble text message → Mumla TTS.

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
import threading

try:
    import configparser
except ImportError:
    import ConfigParser as configparser

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

    # Verify HMAC
    expected_hmac = hmac.new(
        secret.encode('utf-8'),
        payload,
        hashlib.sha256
    ).digest()

    if not hmac.compare_digest(received_hmac, expected_hmac):
        log.warning("HMAC verification failed - invalid secret or tampered packet")
        return None, None

    # Parse payload
    cmd = chr(data[0])
    radio_id = data[1:1 + RADIO_ID_LEN].rstrip(b'\x00').decode('ascii', errors='replace')
    timestamp = struct.unpack('>I', data[9:13])[0]

    # Replay protection
    now = int(time.time())
    age = abs(now - timestamp)
    if age > REPLAY_WINDOW:
        log.warning("Replay rejected: packet age %ds (radio=%s)", age, radio_id)
        return None, None

    if cmd not in ('N', 'P'):
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
        radio_map: dict mapping radio_id -> mumla_username
        e.g. {'radio01': 'TE300K-1', 'radio02': 'TE300K-2'}
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
        for session_id, user in self.mumble.users.items():
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

        log.info("[%s] Moving '%s' → %s (ID %d)",
                 radio_id, username, target_name, target_id)
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

        # Parse radio map from config: [radios] section
        self.radio_map = {}
        self.secret = config.get('security', 'secret')
        self.allowed_ips = set()

        if config.has_section('radios'):
            for radio_id, mumla_user in config.items('radios'):
                self.radio_map[radio_id] = mumla_user

        if config.has_option('security', 'allowed_ips'):
            ips = config.get('security', 'allowed_ips')
            if ips.strip():
                self.allowed_ips = set(ip.strip() for ip in ips.split(','))

    def connect_mumble(self):
        host = self.config.get('mumble', 'host')
        port = self.config.getint('mumble', 'port')
        username = self.config.get('mumble', 'bot_username')
        password = self.config.get('mumble', 'bot_password')

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
            sort_by=self.config.get('channels', 'sort_by'),
            skip_root=self.config.getboolean('channels', 'skip_root'),
            wrap_around=self.config.getboolean('channels', 'wrap_around'),
        )

    def announce(self, radio_id, channel_name, channel_id):
        if not self.config.getboolean('announce', 'mumble_message'):
            return
        username = self.radio_map.get(radio_id)
        if not username:
            return
        user = self.channel_mgr.find_user_by_name(username)
        if not user:
            return
        fmt = self.config.get('announce', 'format')
        msg = fmt.format(channel=channel_name, id=channel_id)
        try:
            self.mumble.users[user['session']].send_text_message(msg)
        except Exception as e:
            log.warning("Failed to send TTS message: %s", e)

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

        direction = 'next' if cmd == 'N' else 'prev'
        name, cid = self.channel_mgr.switch(radio_id, direction)
        if name:
            self.announce(radio_id, name, cid)

    def run(self):
        self.running = True
        self.connect_mumble()
        time.sleep(1)

        # Log setup
        channels = self.channel_mgr.get_sorted_channels()
        log.info("Channels (%d):", len(channels))
        for ch in channels:
            log.info("  [%d] %s", ch['channel_id'], ch['name'])

        log.info("Radio → User mapping:")
        for rid, uname in self.radio_map.items():
            user = self.channel_mgr.find_user_by_name(uname)
            status = f"channel {user['channel_id']}" if user else "NOT CONNECTED"
            log.info("  %s → %s (%s)", rid, uname, status)

        if self.allowed_ips:
            log.info("Allowed source IPs: %s", ', '.join(self.allowed_ips))
        else:
            log.info("Accepting from any IP (use allowed_ips to restrict)")

        # UDP listener
        listen_addr = self.config.get('udp', 'listen_addr')
        listen_port = self.config.getint('udp', 'listen_port')
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((listen_addr, listen_port))
        sock.settimeout(1.0)

        log.info("Listening on UDP %s:%d (HMAC-SHA256, replay window=%ds)",
                 listen_addr, listen_port, REPLAY_WINDOW)
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
# Config
# ============================================================================
def load_config(path):
    config = configparser.ConfigParser()
    defaults = {
        'mumble': {
            'host': '127.0.0.1', 'port': '64738',
            'bot_username': 'ChannelBot', 'bot_password': '',
        },
        'security': {
            'secret': '',
            'allowed_ips': '',
        },
        'udp': {
            'listen_port': '4378', 'listen_addr': '0.0.0.0',
        },
        'channels': {
            'sort_by': 'id', 'skip_root': 'true', 'wrap_around': 'true',
        },
        'announce': {
            'mumble_message': 'true', 'format': '{channel}',
        },
        'logging': {
            'level': 'INFO',
        },
    }
    for section, values in defaults.items():
        if not config.has_section(section):
            config.add_section(section)
        for k, v in values.items():
            config.set(section, k, v)

    if path and os.path.exists(path):
        config.read(path)
    return config


def main():
    import argparse
    p = argparse.ArgumentParser(description='Mumla Channel Bot - Multi-radio')
    p.add_argument('-c', '--config', default='bot_config.ini')
    p.add_argument('--host', help='Mumble server host')
    p.add_argument('--mumla-user', help='Single radio: Mumla username')
    p.add_argument('--radio-id', default='radio01', help='Single radio: ID')
    p.add_argument('--secret', help='Shared secret')
    p.add_argument('--list', action='store_true', help='List channels/users')
    p.add_argument('--gen-secret', action='store_true',
                   help='Generate a random secret and exit')
    args = p.parse_args()

    if args.gen_secret:
        import secrets
        s = secrets.token_urlsafe(32)
        print(f"Generated secret: {s}")
        print("Put this in bot_config.ini [security] secret=")
        print("and in each radio's knob.conf secret=")
        return

    config = load_config(args.config)

    # CLI overrides
    if args.host:
        config.set('mumble', 'host', args.host)
    if args.secret:
        config.set('security', 'secret', args.secret)
    if args.mumla_user:
        if not config.has_section('radios'):
            config.add_section('radios')
        config.set('radios', args.radio_id, args.mumla_user)

    level = getattr(logging, config.get('logging', 'level').upper(), logging.INFO)
    logging.basicConfig(level=level, format='%(asctime)s [%(levelname)s] %(message)s')

    # Validate
    if not config.get('security', 'secret'):
        log.error("No secret configured! Run with --gen-secret to create one, "
                   "then set it in bot_config.ini [security] secret=")
        sys.exit(1)

    if not config.has_section('radios') or not config.options('radios'):
        log.error("No radios configured! Add [radios] section to config, "
                   "e.g. radio01 = TE300K")
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
            print(f"  {user['name']} (session {sess}, channel {user['channel_id']})")
        bot.mumble.stop()
        return

    bot = ChannelBot(config)
    signal.signal(signal.SIGTERM, lambda s, f: bot.stop())
    signal.signal(signal.SIGINT, lambda s, f: bot.stop())
    bot.run()


if __name__ == '__main__':
    main()
