# Mumla Channel Switcher

Hardware knob → channel switching for Mumble/Mumla on TE300K radios.
Supports multiple radios, HMAC-signed packets, and Docker deployment.

## Architecture

```
  TE300K #1                 TE300K #2
  ┌──────────┐              ┌──────────┐
  │  Rotary  │              │  Rotary  │
  │   Knob   │              │   Knob   │
  └────┬─────┘              └────┬─────┘
       │                         │
  ┌────┴─────────┐          ┌───┴──────────┐
  │ knob_reader  │          │ knob_reader   │
  │ radio01      │          │ radio02       │
  │ HMAC-SHA256  │          │ HMAC-SHA256   │
  └──────┬───────┘          └──────┬────────┘
         │  UDP :4378              │
         └────────┬────────────────┘
                  ▼
     ┌─────────────────────────┐
     │  channel-bot (Docker)   │
     │                         │
     │  ✓ Verify HMAC          │
     │  ✓ Check replay window  │
     │  ✓ Check IP allowlist   │
     │  ✓ Move correct user    │
     │  ✓ Send TTS message     │
     └────────────┬────────────┘
                  │ Mumble protocol
                  ▼
     ┌─────────────────────────┐
     │  Mumble Server (Docker) │
     └─────────────────────────┘
```

## Security

| Layer | What | How |
|-------|------|-----|
| Authentication | Every packet signed | HMAC-SHA256 with pre-shared key |
| Replay protection | Reject old packets | 30-second timestamp window |
| IP allowlist | Restrict sources | Optional, in bot_config.ini |
| Per-radio identity | 8-char radio ID | Mapped to Mumble username |

Packets without a valid HMAC are silently dropped. Captured packets
expire after 30 seconds and can't be replayed.

## Quick Start

### 1. Generate a shared secret

```bash
python3 channel_bot.py --gen-secret
# Output: Generated secret: aBcDeFgH...
```

Put this secret in BOTH `bot_config.ini` AND each radio's `knob.conf`.

### 2. Server side (Docker)

Copy these files alongside your existing Mumble `docker-compose.yml`:

```
your-stack/
├── docker-compose.yml      (add the channel-bot service)
├── bot_config.ini          (edit: secret, radio mapping, mumble host)
└── docker/
    └── Dockerfile
```

Edit `bot_config.ini`:
```ini
[mumble]
host = murmur              # your murmur service name in compose

[security]
secret = aBcDeFgH...       # the secret you generated

[radios]
radio01 = TE300K            # radio_id = mumla_username
radio02 = TE300K-2          # add more radios as needed
```

Deploy:
```bash
docker compose up -d --build
```

### 3. Each TE300K radio

Push the binary and config:
```bash
# Edit knob.conf with the radio's unique ID and the shared secret
adb push knob_reader /data/local/tmp/
adb push knob.conf /data/local/tmp/
adb shell chmod 755 /data/local/tmp/knob_reader

# Test
adb shell /data/local/tmp/knob_reader -f /data/local/tmp/knob.conf

# Background (survives ADB disconnect)
adb shell "nohup /data/local/tmp/knob_reader -f /data/local/tmp/knob.conf >/dev/null 2>&1 &"
```

Each radio gets its own `knob.conf` with a unique `radio_id`
(radio01, radio02, ...) but the SAME `secret`.

### 4. Mumble ACL

Grant the bot **Move** permission in your Mumble server ACL.

### 5. Mumla TTS

Enable Text-to-Speech in Mumla settings. The bot sends the channel
name as a text message after each switch, which Mumla reads aloud.

## Files

| File | Where | Purpose |
|------|-------|---------|
| `knob_reader` | TE300K | ARM binary - reads knob, sends signed UDP |
| `knob.conf.example` | TE300K | Per-radio config template |
| `channel_bot.py` | Docker | Python bot - verifies, moves users |
| `bot_config.ini` | Docker | Bot + radio mapping config |
| `docker/Dockerfile` | Docker | Container build file |
| `docker-compose.yml` | Docker | Stack definition |
| `knob_reader.c` | — | Source code (for reference) |

## Adding a New Radio

1. Pick a `radio_id` (max 8 chars): e.g. `radio03`
2. Add to `bot_config.ini` under `[radios]`: `radio03 = NewUserName`
3. Create a `knob.conf` on the new radio with `radio_id=radio03`
4. Restart the bot: `docker compose restart channel-bot`

## Troubleshooting

**HMAC verification failed** — Secret mismatch between radio and bot.
Double-check both `knob.conf` and `bot_config.ini` have the same secret.

**Replay rejected** — The TE300K clock is too far off. Android 6 might
not have correct time if NTP isn't working. Check with `adb shell date`.

**User not found** — The `mumla_username` in `[radios]` must exactly
match what Mumla uses to connect (case-sensitive).

**Bot can't move users** — Grant Move permission in Mumble server ACL.

**UDP not arriving** — Check Docker port mapping (`4378:4378/udp`),
host firewall, and that `knob.conf` has the correct host IP.
