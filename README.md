# Porto Watchdog

Hardware control system for TE300K Mumble radios. Onboard a radio once,
everything auto-starts on boot and runs forever.

Two watchdogs work together:

- **Local watchdog** (`porto-watchdog` binary) — runs in the background on
  each radio, intercepts hardware key events, handles PTT locally and
  forwards knob/button presses to the remote watchdog over UDP.
- **Remote watchdog** (`porto-watchdog` Docker container) — runs on your
  server, receives key events from all radios, switches channels, and
  broadcasts emergency/ident messages through the Mumble server.

## What the Buttons Do

| Input | Key | What happens |
|-------|-----|--------------|
| **PTT button** | F1 | Hold to talk, release to stop (handled locally via Mumla) |
| **Knob clockwise** | F14 | Next channel — forwarded to remote watchdog, TTS announces |
| **Knob counter-clockwise** | F13 | Previous channel — forwarded to remote watchdog |
| **Side button** | F2 | Ident — forwarded to remote watchdog, announces your name |
| **Emergency button** | F3 | Emergency — forwarded to remote watchdog, broadcasts alert |

## How It Works

```
  TE300K Radio (runs in background after boot)
  ┌────────────────────────────────────────────────┐
  │                                                │
  │  PTT (F1)   Ident (F2)   Emergency (F3)        │
  │  Knob CW (F14)     Knob CCW (F13)              │
  │       │         │         │                    │
  │  ┌────┴─────────┴─────────┴────────────────┐   │
  │  │    porto-watchdog (local watchdog)       │  │
  │  │    background daemon on the radio        │  │
  │  │                                          │  │
  │  │    Intercepts /dev/input/event3 + event4 │  │
  │  │    Routes each keypress:                 │  │
  │  │      F1  → local PTT socket              │  │
  │  │      F2  → remote watchdog (UDP)         │  │
  │  │      F3  → remote watchdog (UDP)         │  │
  │  │      F13 → remote watchdog (UDP)         │  │
  │  │      F14 → remote watchdog (UDP)         │  │
  │  └──┬──────────────────────────┬────────────┘  │
  │     │ PTT socket               │ UDP :4378     │
  │  ┌──┴──────────────┐           │               │
  │  │ pttbridge.apk   │           │               │
  │  │ boot autostart  │           │               │
  │  │ PTT → Mumla     │           │               │
  │  └──┬──────────────┘           │               │
  │  ┌──┴──────────────┐           │               │
  │  │     Mumla       │           │               │
  │  └──────┬──────────┘           │               │
  └─────────┼──────────────────────┼───────────────┘
            │ Mumble               │ UDP
            ▼                      ▼
  ┌──────────────────────────────────────────────┐
  │            Server (Docker)                   │
  │                                              │
  │  ┌────────────────┐  ┌────────────────────┐  │
  │  │ Mumble Server  │  │ porto-watchdog     │  │
  │  │                │←─│ (remote watchdog)  │  │
  │  │                │  │ moves users        │  │
  │  │                │  │ broadcasts alerts  │  │
  │  └────────────────┘  └────────────────────┘  │
  └──────────────────────────────────────────────┘
```

The local watchdog runs as a background daemon — it starts on boot,
reads hardware input events continuously, and never needs user
interaction. PTT is handled entirely on the radio (low latency).
Channel switching and alerts are forwarded as signed UDP packets to
the remote watchdog, which executes them on the Mumble server.

## Setup Guide

### Step 1: Server — Deploy the remote watchdog

Do this once on your server.

**1a. Generate secrets**

```bash
docker run --rm rsmcx1/porto-watchdog --gen-secret
```

You can use one shared secret for all radios (`SECRET`), or generate a
separate secret per radio (`SECRETS`) so you can revoke a compromised
radio without re-keying the others.

**1b. Add porto-watchdog to your Docker stack**

Add the service from `docker-compose.yml` to your existing Mumble stack.
The three variables you must set:

```yaml
environment:
  MUMBLE_HOST: your-mumble-container-name
  # Option A: one shared secret for all radios
  SECRET: "the-secret-from-step-1a"
  # Option B: per-radio secrets (revoke one without affecting others)
  # SECRETS: "radio01=secretA,radio02=secretB"
  RADIOS: "radio01=TE300K,radio02=TE300K-2"
```

All other variables have sensible defaults (see full list below).

**1c. Register the bot and grant permissions**

The bot auto-generates a persistent certificate on first start (stored
in the `porto-certs` Docker volume). After the bot connects for the
first time:

1. Open a Mumble client, connect to the same server as an admin
2. Right-click the bot user (`ChannelBot`) and select **Register**
3. Go to the root channel ACL, add `ChannelBot`, and grant **Move** permission

**1d. Open firewall**

The remote watchdog listens on UDP port **4378**. Make sure your
radios can reach it.

### Step 2: Radio — One-time onboarding

Connect the TE300K via USB. Do this once per radio, then unplug and go.

**2a. Unlock app installs**

```bash
adb shell setprop persist.telo.install enable
```

Persists across reboots. Only needed once per device.

**2b. Install the apps**

```bash
adb install pttbridge.apk
adb install mumla.apk
```

**2c. Prepare the radio config**

Copy `knob.conf.example` to `knob.conf` and fill in your values:

```ini
host=192.168.1.100         # IP of your server running the remote watchdog
port=4378                  # must match UDP_PORT on the server
radio_id=radio01           # unique per radio (max 8 chars)
secret=your-secret-here    # same secret as Step 1a
device=/dev/input/event4   # knob input (don't change)
button_device=/dev/input/event3  # button input (don't change)
```

Each radio needs a **unique `radio_id`**. The `secret` must match what
the server has — either the shared `SECRET` or that radio's entry in
`SECRETS`.

**2d. Download the porto-watchdog binary**

Go to the [Actions tab](../../actions) on GitHub, click the latest
successful **Build and Push** run, scroll to **Artifacts**, and download
**porto-watchdog-arm**. Unzip it — the file inside is `porto-watchdog`.

Alternatively, if there is a tagged release, grab it from the
[Releases page](../../releases).

**2e. Push files to the radio**

```bash
adb push porto-watchdog /data/local/tmp/porto-watchdog
adb shell chmod 755 /data/local/tmp/porto-watchdog
adb push knob.conf /data/local/tmp/knob.conf

# Symlink for pttbridge.apk compatibility (it launches ptt_bridge by name)
adb shell ln -sf /data/local/tmp/porto-watchdog /data/local/tmp/ptt_bridge
```

**2f. Start the service**

```bash
adb shell am startservice -a com.pttbridge.START
```

Only needed once. After this, everything auto-starts on every boot.

**2g. Configure Mumla**

Open Mumla on the radio, add your Mumble server, and enable
**Text-to-Speech** in settings so channel names and alerts are
read aloud through the speaker.

### Step 3: Verify

Reboot the radio. On boot, `pttbridge.apk` automatically:
1. Starts the PTT socket service
2. Launches the `porto-watchdog` local watchdog daemon
3. Opens Mumla and connects to your Mumble server

Test everything:
- **Knob** — turn it, you should hear the channel name announced
- **PTT** — hold the button, your voice should transmit
- **Side button (F2)** — your name gets announced to the channel
- **Emergency (F3)** — "alert alert" broadcasts to the channel

**Done. Unplug the USB cable. The radio is onboarded.**

## Adding More Radios

Repeat Step 2 with a different `radio_id` in `knob.conf`.

On the server, update the `RADIOS` env var and restart:

```
RADIOS="radio01=TE300K,radio02=TE300K-2,radio03=TE300K-3"
```

## RADIOS Format

Comma-separated `radio_id=mumla_username` pairs.
Wildcards supported — `*` matches anything, `?` matches one character:

```
RADIOS="radio01=TE300K"                        # exact match
RADIOS="radio01=TE300K,radio02=TE300K-2"       # multiple radios
RADIOS="radio01=P*"                            # any user starting with P
```

## Environment Variables (remote watchdog)

| Variable | Default | Description |
|----------|---------|-------------|
| `MUMBLE_HOST` | 127.0.0.1 | Mumble server hostname |
| `MUMBLE_PORT` | 64738 | Mumble server port |
| `BOT_USERNAME` | ChannelBot | Bot display name in Mumble |
| `BOT_PASSWORD` | *(empty)* | Bot password |
| `SECRET` | *(required)* | HMAC shared secret (fallback for all radios) |
| `SECRETS` | *(empty)* | Per-radio secrets: `radio01=key1,radio02=key2` |
| `ALLOWED_IPS` | *(empty=any)* | Source IP allowlist |
| `UDP_PORT` | 4378 | UDP listen port |
| `UDP_ADDR` | 0.0.0.0 | UDP bind address |
| `CHANNELS_SORT_BY` | id | Channel order: `id` or `name` |
| `CHANNELS_SKIP_ROOT` | true | Skip root channel |
| `CHANNELS_WRAP_AROUND` | true | Wrap at channel boundaries |
| `ANNOUNCE_ENABLED` | true | TTS channel name on switch |
| `ANNOUNCE_FORMAT` | {channel} | Channel announce template |
| `EMERGENCY_FORMAT` | alert alert | Emergency broadcast message |
| `IDENT_FORMAT` | {username} | Ident broadcast template |
| `LOG_LEVEL` | INFO | DEBUG, INFO, WARNING, ERROR |
| `RADIOS` | *(required)* | Radio-to-user mapping |

## Security

All key events forwarded to the remote watchdog are authenticated.

| Layer | How |
|-------|-----|
| Authentication | Every UDP packet signed with HMAC-SHA256 |
| Per-radio keys | Optional per-radio secrets via `SECRETS` env var |
| Replay protection | Packets expire after 30 seconds |
| IP allowlist | Optional `ALLOWED_IPS` env var |
| Per-radio identity | 8-char radio ID in every packet |

Unsigned or expired packets are silently dropped.

**Revoking a compromised radio:** If using per-radio secrets (`SECRETS`),
remove or replace that radio's entry and restart the container. All other
radios keep working. If using a shared secret (`SECRET`), all radios
must be re-keyed.

## Files

| File | Where | What |
|------|-------|------|
| `knob_reader.c` | Source | C source for the local watchdog binary |
| `knob.conf.example` | Radio | Per-radio config template |
| `channel_bot.py` | Docker | Remote watchdog server |
| `docker-compose.yml` | Docker | Stack definition |
| `docker/Dockerfile` | Docker | Container build |

Binaries are built automatically by CI — download `porto-watchdog` from
the [Actions](../../actions) tab (artifact: `porto-watchdog-arm`).

## Troubleshooting

**Apps won't install** —
`adb shell setprop persist.telo.install enable`

**PTT not working** —
`adb shell dumpsys activity services | grep pttbridge`
If not running: `adb shell am startservice -a com.pttbridge.START`

**Channel switch / emergency / ident not working** —
Check `knob.conf` on the radio: `host` must be reachable from the
radio's network. Check UDP port 4378 is open. Check remote watchdog
container logs.

**"HMAC verification failed"** —
`secret` in `knob.conf` must match the server's `SECRET` or that
radio's entry in `SECRETS`.

**"Replay rejected"** —
Radio clock is off. Check: `adb shell date`

**"User not found"** —
Username in `RADIOS` must match Mumla's connection name (case-sensitive).
Use `P*` wildcards if the name varies.

**Bot can't move users** —
Grant Move permission in Mumble ACL for the bot user.

**No TTS** —
Enable Text-to-Speech in Mumla settings on the radio.
