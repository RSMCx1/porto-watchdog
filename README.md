# Mumla Channel Switcher

Hardware knob + button control for Mumble/Mumla on TE300K radios.
Supports multiple radios, emergency alerts, ident broadcasts, HMAC-signed
packets, wildcard user matching, and Docker deployment.

## Architecture

```
  TE300K #1                     TE300K #2
  ┌──────────────────┐          ┌──────────────────┐
  │  Knob  F2  F3    │          │  Knob  F2  F3    │
  │  N/P  Ident Emrg │          │  N/P  Ident Emrg │
  └───┬────┬────┬────┘          └───┬────┬────┬────┘
      │    │    │                    │    │    │
  ┌───┴────┴────┴────┐          ┌───┴────┴────┴────┐
  │   knob_reader     │          │   knob_reader     │
  │   radio01         │          │   radio02         │
  │   HMAC-SHA256     │          │   HMAC-SHA256     │
  └────────┬──────────┘          └────────┬──────────┘
           │  UDP :4378                   │
           └──────────┬───────────────────┘
                      ▼
         ┌──────────────────────────┐
         │  channel-bot (Docker)    │
         │                          │
         │  N/P → Move user + TTS  │
         │  E   → "alert alert"    │
         │  I   → username ident   │
         └────────────┬─────────────┘
                      │ Mumble protocol
                      ▼
         ┌──────────────────────────┐
         │  Mumble Server (Docker)  │
         └──────────────────────────┘
```

## Features

| Feature | Button | Command | Behavior |
|---------|--------|---------|----------|
| Next channel | Knob clockwise (KEY_F14) | N | Moves radio user to next channel, TTS announces name |
| Prev channel | Knob counter-clockwise (KEY_F13) | P | Moves radio user to previous channel, TTS announces name |
| Emergency | F3 button (KEY_F3) | E | Broadcasts "alert alert" to all users in the channel |
| Ident | F2 side button (KEY_F2) | I | Broadcasts username to all users in the channel |

## Security

| Layer | What | How |
|-------|------|-----|
| Authentication | Every packet signed | HMAC-SHA256 with pre-shared key |
| Replay protection | Reject old packets | 30-second timestamp window |
| IP allowlist | Restrict sources | Optional `ALLOWED_IPS` env var |
| Per-radio identity | 8-char radio ID | Mapped to Mumble username |

## Quick Start

### 1. Generate a shared secret

```bash
docker run --rm rsmcx1/porto-watchdog --gen-secret
# Output: Generated secret: aBcDeFgH...
```

### 2. Server side (Docker)

Add the `channel-bot` service to your existing Mumble docker-compose stack.
All config is via environment variables — no config files needed.

Key variables to set in your stack:

```yaml
environment:
  MUMBLE_HOST: your-mumble-service-name
  SECRET: "the-secret-you-generated"
  RADIOS: "radio01=TE300K,radio02=TE300K-2"
```

See `docker-compose.yml` for the full list with defaults.

**Wildcard matching:** Use `*` in radio usernames to match patterns.
Example: `RADIOS="radio01=P*"` matches any connected user starting with P.

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

Each radio gets its own `knob.conf` with a unique `radio_id` but the SAME `secret`.

The `knob_reader` ARM binary is built automatically by CI — download it from
the [Actions](../../actions) tab (artifact: `knob_reader-arm`).

### 4. Mumble ACL

Grant the bot **Move** permission in your Mumble server ACL.

### 5. Mumla TTS

Enable Text-to-Speech in Mumla settings. The bot sends channel names
and alerts as text messages, which Mumla reads aloud.

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `MUMBLE_HOST` | 127.0.0.1 | Mumble server hostname |
| `MUMBLE_PORT` | 64738 | Mumble server port |
| `BOT_USERNAME` | ChannelBot | Bot display name |
| `BOT_PASSWORD` | *(empty)* | Bot password |
| `SECRET` | *(required)* | HMAC shared secret |
| `ALLOWED_IPS` | *(empty=any)* | Comma-separated source IP allowlist |
| `UDP_PORT` | 4378 | UDP listen port |
| `UDP_ADDR` | 0.0.0.0 | UDP bind address |
| `CHANNELS_SORT_BY` | id | Channel sort: `id` or `name` |
| `CHANNELS_SKIP_ROOT` | true | Skip root channel |
| `CHANNELS_WRAP_AROUND` | true | Wrap at channel boundaries |
| `ANNOUNCE_ENABLED` | true | TTS channel announcements |
| `ANNOUNCE_FORMAT` | {channel} | Channel announce template |
| `EMERGENCY_FORMAT` | alert alert | Emergency broadcast message |
| `IDENT_FORMAT` | {username} | Ident broadcast template |
| `LOG_LEVEL` | INFO | Log level |
| `RADIOS` | *(required)* | Radio mapping (see below) |

### RADIOS format

Comma-separated `radio_id=mumla_username` pairs. Supports `*` and `?` wildcards.

```
RADIOS="radio01=TE300K"
RADIOS="radio01=TE300K,radio02=TE300K-2,radio03=TE300K-3"
RADIOS="radio01=P*"
```

## Files

| File | Where | Purpose |
|------|-------|---------|
| `knob_reader.c` | Radio (source) | C source - reads knob + buttons, sends signed UDP |
| `knob_reader` | Radio (binary) | Pre-built ARM binary |
| `knob.conf.example` | Radio | Per-radio config template |
| `channel_bot.py` | Docker | Python bot - verifies packets, moves users, broadcasts |
| `docker/Dockerfile` | Docker | Container build file |
| `docker-compose.yml` | Docker | Stack definition with all env vars |

## Adding a New Radio

1. Pick a `radio_id` (max 8 chars): e.g. `radio03`
2. Add to `RADIOS` env var: `radio01=TE300K,radio02=TE300K-2,radio03=NewUser`
3. Create a `knob.conf` on the new radio with `radio_id=radio03`
4. Restart the bot: `docker compose restart channel-bot`

## Troubleshooting

**HMAC verification failed** — Secret mismatch between radio and bot.
Check both `knob.conf` and `SECRET` env var have the same value.

**Replay rejected** — The TE300K clock is too far off. Check with `adb shell date`.

**User not found** — The username in `RADIOS` must match what Mumla connects as
(case-sensitive). Use wildcards like `P*` if the exact name varies.

**Bot can't move users** — Grant Move permission in Mumble server ACL.

**UDP not arriving** — Check Docker port mapping (`4378:4378/udp`),
host firewall, and that `knob.conf` has the correct host IP.

**Buttons not working** — Check `button_device` in `knob.conf` points to the
correct `/dev/input/eventX`. Run `adb shell getevent -l` and press the buttons.
