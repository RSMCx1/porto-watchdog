# Porto Watchdog

After years of using cheap Baofeng radios with poor audio quality and limited range, it was time to step up to PTT over Cellular (PoC). Unfortunately, most PoC radios ship with locked-down firmware restricted to a handful of closed-source apps that require monthly license fees. Finding something worth buying when you only use it a few times a year - and want to keep communications private - is a real challenge.

You can't have it all, so some concessions had to be made. The non-negotiable requirement: the radio must run Android, so third-party VoIP apps can be installed. This makes it possible to self-host voice services and encrypt communications end-to-end, keeping things private for family and friends. A bonus would be enough disk space, memory, and CPU headroom to run something like a GPS tracker feeding into CivTAK.

The TE300K checked those boxes. With the help of [Anthropic's](https://www.anthropic.com) AI I have created Porto Watchdog - the software that ties it all together, turning the physical knob, buttons, and PTT into a seamless Mumble radio experience. Onboard a radio once, everything auto-starts on boot and runs forever.

![Demo](demo.gif)

## How It Works

Two watchdogs work together:

- **Local watchdog** (`porto-watchdog` binary) - runs in the background on
  each radio, intercepts hardware key events, handles PTT locally and
  forwards knob/button presses to the remote watchdog over UDP.
- **Remote watchdog** (`porto-watchdog` Docker container) - runs on your
  server, receives key events from all radios, switches channels, and
  broadcasts emergency/ident messages through the Mumble server.

### Button Mapping

| Input | Key | What happens |
|-------|-----|--------------|
| **PTT button** | F1 | Hold to talk, release to stop (handled locally via Mumla) |
| **Knob clockwise** | F14 | Next channel - forwarded to remote watchdog, TTS announces |
| **Knob counter-clockwise** | F13 | Previous channel - forwarded to remote watchdog |
| **Side button** | F2 | Ident - forwarded to remote watchdog, announces your name |
| **Emergency button** | F3 | Emergency - forwarded to remote watchdog, broadcasts alert |

### Architecture

```
  TE300K Radio (runs in background after boot)
  ┌────────────────────────────────────────────────┐
  │                                                │
  │      PTT (F1)   Ident (F2)   Emergency (F3)    │
  │        Knob CW (F14)     Knob CCW (F13)        │
  │       │         │         │                    │
  │  ┌────┴─────────┴─────────┴─────────────────┐  │
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

The local watchdog runs as a background daemon - it starts on boot,
reads hardware input events continuously, and never needs user
interaction. PTT is handled entirely on the radio (low latency).
Channel switching and alerts are forwarded as signed UDP packets to
the remote watchdog, which executes them on the Mumble server.

### The Mumble bot

The remote watchdog is a Python bot built on
[pymumble](https://github.com/azlux/pymumble). It connects to your
Mumble server as a regular user, listens for signed UDP packets from
the radios, and translates them into Mumble actions: moving users
between channels, sending text messages (which Mumla reads aloud via
TTS), and broadcasting emergency or ident alerts.

Every packet that arrives is verified before anything happens. The bot
checks the HMAC-SHA256 signature against the radio's secret, rejects
anything older than 30 seconds to prevent replay attacks, and
optionally restricts source IPs. Per-radio secrets mean you can revoke
a single compromised radio without touching the others. Unsigned,
expired, or unknown packets are silently dropped - nothing gets
through without a valid signature.

The bot auto-generates a TLS client certificate on first start and
stores it in a Docker volume. This gives it a persistent identity on
the Mumble server, so ACL permissions (like the ability to move users)
survive container restarts. All configuration is done through
environment variables - no config files to manage.

## Making It Work - The Hard Parts

### Platform signing: becoming a system app

The local watchdog needs to read raw hardware events from `/dev/input/event3`
(buttons) and `/dev/input/event4` (knob). On Android, those device files are
owned by `root:input` - regular apps can't touch them. The
`android.permission.DIAGNOSTIC` permission grants access to the `input` group,
but it's a signature-level permission: Android only grants it if the APK is
signed with the same key as the firmware itself.

Here's the trick: many OEMs - including whoever builds the TE300K firmware -
never bother generating their own platform signing keys. They ship with the
default AOSP test keys that Google publishes in the Android source tree. Those
keys are public. Anyone can download `platform.x509.pem` and `platform.pk8`
from AOSP and sign an APK with them.

That's exactly what `pttbridge.apk` does. It's signed with the AOSP default
platform keys, and the TE300K firmware accepts it as a trusted system app.
This gives us:

- **`android.permission.DIAGNOSTIC`** - access to `/dev/input/*` devices, so
  the watchdog binary can read knob turns and button presses directly from
  the kernel
- **`RECEIVE_BOOT_COMPLETED`** - fires reliably on every boot, even on
  locked-down firmware that might throttle or suppress third-party boot
  receivers
- **`Runtime.exec()`** - the binary launched by the service inherits the
  app's UID and group memberships, so it can open the input devices without
  root

Without platform signing, none of this works. The binary would get
"Permission denied" on the input devices, and you'd need root access to the
radio - which the TE300K doesn't offer.

### Unlocking app installs: `persist.telo.install`

Out of the box, the TE300K won't let you install apps. Running `adb install`
fails silently or returns an error. The firmware's package installer has a
gatekeeper: a system property that must be set before sideloading is allowed.

Finding it required dumping all system properties (`adb shell getprop`) and
looking for anything Telo/Inrico-specific. Buried in the output:
`persist.telo.install` - a custom property the firmware checks before
allowing APK installs. Setting it to `enable` flips the switch:

```bash
adb shell setprop persist.telo.install enable
```

The `persist.` prefix means it survives reboots - set it once and forget it.
Without this, there's no way to get Mumla or pttbridge onto the radio short
of modifying the system partition.

## Setup Guide

### Step 1: Server - Deploy the remote watchdog

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

### Step 2: Radio - One-time onboarding

You need [Android SDK Platform Tools](https://developer.android.com/tools/releases/platform-tools)
installed on your computer for the `adb` command. Download the ZIP, extract
it, and make sure `adb` is in your PATH. Connect the TE300K via USB.

**2a. Unlock app installs**

The TE300K blocks sideloading by default (see [above](#unlocking-app-installs-persistteloinstall)).
Flip the switch:

```bash
adb shell setprop persist.telo.install enable
```

Persists across reboots. Only needed once per device.

**2b. Install the apps**

Both APKs are included in this repo. [Mumla](https://github.com/quite/mumla)
is an open-source Mumble client (GPL-3.0). You must use **version 3.6.15
(build 110)** - newer versions crash on the second launch when acknowledging
the changelog on Android 6.0. The correct version is included as `mumla.apk`.

```bash
adb install pttbridge.apk
adb install mumla.apk
```

**2c. Prepare the radio config**

Copy `knob.conf.example` to `knob.conf` and fill in your values:

```ini
host=192.168.1.100         # IP or hostname of your server (DNS supported)
port=4378                  # must match UDP_PORT on the server
radio_id=radio01           # unique per radio (max 8 chars)
secret=your-secret-here    # same secret as Step 1a
device=/dev/input/event4   # knob input (don't change)
button_device=/dev/input/event3  # button input (don't change)
```

Each radio needs a **unique `radio_id`**. The `secret` must match what
the server has - either the shared `SECRET` or that radio's entry in
`SECRETS`.

**2d. Download the porto-watchdog binary**

Grab `porto-watchdog` from the [latest release](../../releases/latest).

Alternatively, go to the [Actions tab](../../actions), click the latest
successful **Build and Push** run, scroll to **Artifacts**, and download
**porto-watchdog-arm**.

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

**TTS and the bot name:** Mumla's TTS reads incoming text messages as
"*BotName* says *message*". The `BOT_USERNAME` on the server controls
what gets spoken before every announcement. You have a few options:
pick something short and natural (e.g. `Radio` - you'd hear "Radio
says General"), or silence the bot name entirely by setting it to a
character that TTS ignores (e.g. `|`). With `|` as the bot name, TTS
just reads the message itself with no prefix. That's what I use.

### Step 3: Verify

Reboot the radio. On boot, `pttbridge.apk` automatically:
1. Starts the PTT socket service
2. Launches the `porto-watchdog` local watchdog daemon
3. Opens Mumla and connects to your Mumble server
4. Returns to the home screen after connecting

Test everything:
- **Knob** - turn it, you should hear the channel name announced
- **PTT** - hold the button, your voice should transmit
- **Side button (F2)** - your name gets announced to the channel
- **Emergency (F3)** - "alert alert" broadcasts to the channel

**Done. Unplug the USB cable. The radio is onboarded.**

## Adding More Radios

Repeat Step 2 with a different `radio_id` in `knob.conf`.

On the server, update the `RADIOS` env var and restart:

```
RADIOS="radio01=TE300K,radio02=TE300K-2,radio03=TE300K-3"
```

## RADIOS Format

Comma-separated `radio_id=mumla_username` pairs.
Wildcards supported - `*` matches anything, `?` matches one character:

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
| `MUMBLE_SERVER_PASSWORD` | *(empty)* | Mumble server password |
| `SECRET` | *(required)* | HMAC shared secret (fallback for all radios) |
| `SECRETS` | *(empty)* | Per-radio secrets: `radio01=key1,radio02=key2` |
| `ALLOWED_IPS` | *(empty=any)* | Source IP allowlist |
| `UDP_PORT` | 4378 | UDP listen port |
| `UDP_ADDR` | 0.0.0.0 | UDP bind address |
| `CHANNELS_SORT_BY` | id | Channel order: `id` or `name` |
| `CHANNELS_SKIP_ROOT` | true | Skip root channel |
| `CHANNELS_WRAP_AROUND` | true | Wrap at channel boundaries |
| `CHANNELS_SKIP` | *(empty)* | Channel names to skip (comma-separated) |
| `ANNOUNCE_ENABLED` | true | TTS channel name on switch |
| `ANNOUNCE_FORMAT` | {channel} | Channel announce template |
| `EMERGENCY_FORMAT` | alert alert | Emergency broadcast message (`{username}` supported) |
| `IDENT_FORMAT` | {username} | Ident broadcast template |
| `CONNECT_MESSAGE_ENABLED` | true | Send message when a radio joins |
| `CONNECT_MESSAGE_FORMAT` | {username} {channel} connected | Connect message template |
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
| `pttbridge.apk` | Radio | Boot autostart + PTT socket bridge + Mumla auto-connect |
| `mumla.apk` | Radio | Mumla v3.6.15 - open-source Mumble client ([GPL-3.0](https://github.com/quite/mumla)) |

Binaries are built automatically by CI - download `porto-watchdog` from
the [latest release](../../releases/latest) or the
[Actions](../../actions) tab (artifact: `porto-watchdog-arm`).

## Troubleshooting

- **Apps won't install** - `adb shell setprop persist.telo.install enable`
- **PTT not working** - `adb shell dumpsys activity services | grep pttbridge`. If not running: `adb shell am startservice -a com.pttbridge.START`
- **Channel switch / emergency / ident not working** - check `knob.conf` on the radio: `host` must be reachable from the radio's network. Check UDP port 4378 is open. Check remote watchdog container logs: `docker logs porto-watchdog`
- **"HMAC verification failed"** - `secret` in `knob.conf` must match the server's `SECRET` or that radio's entry in `SECRETS`
- **"Replay rejected"** - radio clock is off. Check: `adb shell date`
- **"User not found"** - username in `RADIOS` must match Mumla's connection name (case-sensitive). Use `P*` wildcards if the name varies
- **Bot can't move users** - grant Move permission in Mumble ACL for the bot user
- **Auto-start not working after reboot** - check logcat: `adb shell logcat -d | grep -i pttbridge`. Also check the binary exists: `adb shell ls -la /data/local/tmp/porto-watchdog` and the symlink: `adb shell ls -la /data/local/tmp/ptt_bridge`
- **DNS not resolving on the radio** - check logcat: `adb shell logcat -d | grep porto-watchdog`. If you see "DNS not ready", the radio's WiFi may not be connected yet. The binary retries DNS on every keypress. You can also use an IP address directly in `knob.conf` to bypass DNS entirely
- **No TTS** - enable Text-to-Speech in Mumla settings on the radio

## Roadmap

- **GPS tracking** - enable GPS functionality on the radios for location sharing, useful for integration with platforms like CivTAK for shared situational awareness
- **LED control** - adjust LED behavior based on external input and user preferences
- **Home screen LCD** - replace the stock home screen with a custom display showing current channel, signal status, and radio info on the TE300K's small screen
