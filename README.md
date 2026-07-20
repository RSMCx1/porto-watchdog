# Porto Watchdog

After years of using cheap Baofeng radios with poor audio quality and limited range, it was time to step up to PTT over Cellular (PoC). Unfortunately, most PoC radios ship with locked-down firmware restricted to a handful of closed-source apps that require monthly license fees. Finding something worth buying when you only use it a few times a year - and want to keep communications private - is a real challenge.

You can't have it all, so some concessions had to be made. The non-negotiable requirement: the radio must run Android, so third-party VoIP apps can be installed. This makes it possible to self-host voice services and encrypt communications end-to-end, keeping things private for family and friends. A bonus would be enough disk space, memory, and CPU headroom to run something like a GPS tracker feeding into [TAK](https://tak.gov).

The TE300K checked those boxes. With the help of [Anthropic's](https://www.anthropic.com) AI I have created Porto Watchdog - the software that ties it all together, turning the physical knob, buttons, and PTT into a seamless Mumble radio experience. Onboard a radio once, everything auto-starts on boot and runs forever.

![Demo](demo.gif)

## Features

- **Push-to-talk** - press the physical PTT button on the radio and your voice goes out instantly, even with the app running in the background. No screen interaction needed
- **Speaker-mic (RSM) support** - plug in a remote speaker microphone and its PTT and emergency buttons work exactly like the radio's own
- **Channel knob** - turn the knob on the radio to switch between channels, just like a traditional two-way radio
- **Voice announcements** - the radio speaks the channel name out loud every time you switch, so you always know where you are without looking at the screen
- **Emergency alert** - press the emergency button and everyone in your channel hears an alert broadcast through their speaker; with TAK enabled, a 911 alert also pops up on every ATAK/WinTAK map at the radio's last known position
- **Ident** - press the side button and your name is announced to the channel, useful for roll calls or check-ins
- **Connect notification** - when a radio powers on and joins the server, it receives a spoken confirmation that it is connected and which channel it is in
- **Fully customizable** - every announcement, alert message, and notification can be changed to say whatever you want
- **Channel management** - choose which channels are available on the knob, skip channels you don't need, control the order they appear in
- **GPS tracking** - radios report their position to a [TAK](https://tak.gov) server, so the whole fleet shows up live on the map in ATAK/WinTAK. Opt-in per radio, off by default, coordinates encrypted in transit - and the bot can enroll its own TAK certificate, so there are no certificate files to manage
- **Persistent map presence & track history** - radios that power off or lose coverage stay on the TAK map as "last known" markers (surviving server restarts too), and every position is logged server-side with one-command GPX export and on-map trails: a rolling recent-hours line per radio, plus any past date or range on demand - just ask in TAK chat ("trail P1 yesterday")
- **Channel display on the radio** - the radio's idle screen can show the live Mumble channel name (or "Disconnected"), fed by the server over the same signed UDP link
- **Secured communications** - every command between the radio and server is cryptographically signed and verified
- **Per-radio keys** - each radio can have its own secret key, so if one radio is lost or compromised you can revoke it without affecting the rest of your fleet
- **Zero-touch operation** - power on the radio and walk away. Everything starts automatically, connects to the server, and returns to the home screen. No screen taps required after initial setup
- **Self-healing** - a watchdog on the radio checks every minute that Mumla and the local daemon are alive and relaunches whichever died. No adb cable needed in the field
- **Server runs anywhere** - the server side runs as a Docker container with all settings configured through environment variables, making it easy to deploy on any machine or manage through Portainer

## How It Works

Two watchdogs work together:

- **Local watchdog** (`porto-watchdog` binary) - runs in the background on
  each radio, intercepts hardware key events, handles PTT locally (body
  button and RSM speaker-mic alike) and forwards knob/button presses -
  and, when GPS is enabled, encrypted position reports - to the remote
  watchdog over UDP.
- **Remote watchdog** (`porto-watchdog` Docker container) - runs on your
  server, receives key events from all radios, switches channels,
  broadcasts emergency/ident messages through the Mumble server, and
  optionally forwards radio positions to a TAK server.

### Button Mapping

| Input | Key | What happens |
|-------|-----|--------------|
| **PTT button** | F1 | Hold to talk, release to stop (handled locally via Mumla) |
| **RSM PTT** (speaker-mic) | F1 | Same as body PTT - hold to talk from the external speaker-mic |
| **Knob clockwise** | F14 | Next channel - forwarded to remote watchdog, TTS announces |
| **Knob counter-clockwise** | F13 | Previous channel - forwarded to remote watchdog |
| **Side button** | F2 | Ident - forwarded to remote watchdog, announces your name; also cancels the radio's active TAK emergency alert |
| **Emergency button** (body or RSM) | F3 | Emergency - forwarded to remote watchdog, broadcasts alert |
| **GPS** (optional) | - | Position reports - encrypted, forwarded to the TAK server if configured |

### Architecture

```
  TE300K Radio (runs in background after boot)
  ┌────────────────────────────────────────────────┐
  │                                                │
  │ PTT (F1) RSM PTT (F1) Ident (F2) Emergency (F3)│
  │        Knob CW (F14)     Knob CCW (F13)        │
  │       │         │         │                    │
  │  ┌────┴─────────┴─────────┴─────────────────┐  │
  │  │    porto-watchdog (local watchdog)       │  │
  │  │    background daemon on the radio        │  │
  │  │                                          │  │
  │  │    Intercepts /dev/input/event2 + 3 + 4  │  │
  │  │    Routes each keypress:                 │  │
  │  │      F1  → local PTT socket (body + RSM) │  │
  │  │      F2  → remote watchdog (UDP)         │  │
  │  │      F3  → remote watchdog (UDP)         │  │
  │  │      F13 → remote watchdog (UDP)         │  │
  │  │      F14 → remote watchdog (UDP)         │  │
  │  │    Encrypts GPS fixes → 'L' packet (UDP) │  │
  │  └──┬────────────────▲─────────┬────────────┘  │
  │     │ PTT socket     │ GPS     │ UDP :4378     │
  │  ┌──┴────────────────┴────┐    │               │
  │  │ pttbridge.apk          │    │               │
  │  │ boot autostart         │    │               │
  │  │ PTT → Mumla            │    │               │
  │  │ GPS → socket porto_loc │    │               │
  │  └──┬─────────────────────┘    │               │
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
  │  │                │  │ decrypts positions │  │
  │  └────────────────┘  └─────────┬──────────┘  │
  │                                │ CoT XML     │
  │                                ▼ over TLS    │
  │                      ┌─────────┬──────────┐  │
  │                      │ TAK server         │  │
  │                      │ (optional) → ATAK  │  │
  │                      └────────────────────┘  │
  └──────────────────────────────────────────────┘
```

The local watchdog runs as a background daemon - it starts on boot,
reads hardware input events continuously, and never needs user
interaction. PTT is handled entirely on the radio (low latency),
whether it comes from the body button or an attached speaker-mic.
Channel switching and alerts are forwarded as signed UDP packets to
the remote watchdog, which executes them on the Mumble server. GPS
fixes, when enabled, ride the same UDP channel as encrypted 'L'
packets and end up as live markers on the TAK map. The same path
carries signed replies back: the server answers every radio packet
(and a minutely heartbeat) with the radio's current channel name,
which the radio can show on its idle screen.

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

Position reports get one extra step: the coordinate block is
decrypted (each radio's keystream derives from its existing secret),
turned into a Cursor-on-Target event, and streamed to the TAK server
over a persistent TLS connection - see
[GPS Tracking](#gps-tracking-tak-integration).

The bot auto-generates a TLS client certificate on first start and
stores it in a Docker volume (`CERT_DIR`, default `/app/certs`). This
gives it a persistent identity on the Mumble server, so ACL
permissions (like the ability to move users) survive container
restarts. The same volume holds the TAK client certificate when
self-enrollment is used. All configuration is done through
environment variables - no config files to manage.

## Making It Work - The Hard Parts

### Platform signing: becoming a system app

The local watchdog needs to read raw hardware events from
`/dev/input/event2` (speaker-mic), `/dev/input/event3` (buttons) and
`/dev/input/event4` (knob). On Android, those device files are
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
GPS position reporting to a TAK server is optional and can be added
at any time - see [GPS Tracking](#gps-tracking-tak-integration).

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
button_device=/dev/input/event3  # side buttons (remove line to disable)
ptt_device=/dev/input/event2     # RSM speaker-mic PTT (remove line to disable)
```

GPS is deliberately not part of this file - it is enabled per radio
later via `loc.conf` (see [GPS Tracking](#gps-tracking-tak-integration)).

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
- **RSM PTT** - plug in a speaker-mic, hold its button - same as body PTT
- **Side button (F2)** - your name gets announced to the channel
- **Emergency (F3)** - "alert alert" broadcasts to the channel; with
  TAK enabled, a 911 alert also pops on the ATAK map

**Done. Unplug the USB cable. The radio is onboarded.**

## GPS Tracking (TAK integration)

Radios can report their GPS position through the same signed UDP channel
used for buttons and the knob. The remote watchdog translates each
position report into a Cursor-on-Target event and streams it to a TAK
server, where every radio appears as a live marker in ATAK / WinTAK /
WebTAK. Nothing else is installed on the radio - `pttbridge.apk` reads
the GPS and hands fixes to the local watchdog.

How it flows:

```
GPS fix -> pttbridge.apk -> porto-watchdog (local)
        -> encrypted+signed UDP 'L' packet -> porto-watchdog (remote)
        -> CoT XML over TLS -> TAK server -> ATAK map
```

The feature is **off by default** on both ends.

Only the radio -> server hop ever crosses the internet, and it rides
the same signed, encrypted UDP channel as the knob and buttons. The
server -> TAK hop is server-to-server, no matter where the radios
roam.

**Server side** - point the remote watchdog at your TAK server.
Three options:

*Option A (recommended): self-enrollment.* The bot requests its own
client certificate from the TAK server's enrollment API (port 8446 -
the same mechanism ATAK phones use for Quick Connect) and re-enrolls
automatically when the certificate is within 30 days of expiry. No
certificate files to create, copy, or mount.

1. Create an enrollment user on the TAK server (once):
   ```bash
   docker exec -it takserver bash -c \
     "cd /opt/tak && java -jar utils/UserManager.jar usermod -p '<password>' porto"
   ```
   TAK enforces password complexity: minimum 15 characters with at
   least one uppercase, one lowercase, one digit, and one special
   character.
2. Set on the porto-watchdog container:
   ```yaml
   TAK_HOST: your-tak-server
   TAK_ENROLL_USER: "porto"
   TAK_ENROLL_PASS: "<password>"
   ```
   That's all - enrollment implies TLS and defaults the port to the
   stock 8089 input. The issued certificate is stored in the
   `porto-certs` volume (already in the stock compose file), so it
   survives restarts and the bot only talks to the enrollment API
   when the certificate is missing or about to expire.

*Option B: manual client certificate.* Same TLS input, but you issue
and distribute the certificate yourself:

1. Issue a client certificate on the TAK server (uses the CA you
   created during TAK setup):
   ```bash
   docker exec -it takserver bash -c \
     "cd /opt/tak/certs && ./makeCert.sh client porto-bot"
   ```
2. Copy `certs/files/porto-bot.pem`, `porto-bot.key` and `ca.pem` to
   the porto-watchdog host and mount them into the container
   (e.g. `./takcerts:/app/takcerts:ro`).
3. Set on the porto-watchdog container:
   ```yaml
   TAK_HOST: your-tak-server
   TAK_PORT: "8089"
   TAK_TLS: "true"
   TAK_CA_FILE: /app/takcerts/ca.pem
   TAK_CERT_FILE: /app/takcerts/porto-bot.pem
   TAK_KEY_FILE: /app/takcerts/porto-bot.key
   TAK_KEY_PASS: "atakatak"        # makeCert.sh default key password
   ```
   Client certs expire (makeCert.sh default ~2 years) - regenerate
   and swap the files when they do.

*Option C: plain streaming input (trusted networks only).* Create an
input in the TAK web UI (**Configuration -> Input Manager -> Add
Input**): protocol **STCP**, port `8087`, auth Anonymous, and set
`TAK_HOST` + `TAK_PORT: "8087"` with `TAK_TLS: "false"`. Anyone who
can reach that port can read the live position feed and inject
markers - never expose it beyond a trusted LAN.

Optional for all three: friendly names on the map via
`TAK_CALLSIGNS: "radio01=Dad,radio02=Mom"`. Without it the marker
uses the radio's Mumla username (or radio_id if the mapping is a
wildcard).

**Radio side** - one-time, per radio:

```bash
# Grant the location permission to pttbridge (needed once)
adb shell pm grant com.pttbridge android.permission.ACCESS_FINE_LOCATION

# Make sure the GPS provider is enabled on the device
adb shell settings put secure location_providers_allowed +gps

# Opt in: GPS update interval in seconds (delete the file to disable)
adb shell "echo 30 > /data/local/tmp/loc.conf"
```

Reboot the radio. About 20 seconds after boot, `pttbridge.apk` reads
`loc.conf` and starts listening to the GPS at the configured interval;
each fix is forwarded as a signed `'L'` packet. The local watchdog
additionally rate-limits reports to one per 5 seconds.

For a radio onboarded before GPS support existed, two updates are
needed first: install the current app (`adb install -r pttbridge.apk`
- granted permissions and boot-start behavior survive upgrades) and
re-push the current `porto-watchdog` binary (Steps 2d-2e; the 'L'
position packet is built by the binary itself, so an outdated binary
silently drops GPS fixes). Then run the three commands above and
reboot.

No TAK configuration ever touches the radio: position reports travel
over the same UDP channel (and port) as the knob and buttons, so any
radio that can switch channels can report positions - from any
network, including public cellular.

Notes:

- The interval is a trade-off between map freshness, battery, and
  mobile data. 30-60s is plenty for vehicles; data usage is negligible
  (~60 bytes UDP per report).
- Position packets carry lat/lon, altitude, speed, course, and GPS
  accuracy, and are HMAC-signed and replay-protected like every other
  packet. A radio with no `loc.conf` never touches the GPS at all.
- Coordinates are **encrypted in transit**: the position block of
  every report is encrypted with a key derived from the radio's
  existing secret, with a fresh random nonce per packet
  (encrypt-then-MAC). An observer on the network path sees that a
  radio reported, but not where it is. No extra keys to generate or
  distribute - it all derives from the `secret=` already in
  `knob.conf`.
- **The emergency button reaches the TAK map too**: when a radio with
  GPS triggers an emergency, the bot raises a 911 alert
  (`b-a-o-tbl`) at the radio's last reported position - it alarms on
  every connected ATAK/WinTAK client and clears itself after
  `TAK_EMERGENCY_STALE` seconds (default 300). Pressing the **ident
  button cancels the radio's active alert immediately** (a proper TAK
  cancel plus a force-stale tombstone for clients that ignore
  cancels) - the voice ident still happens as usual, and active
  alerts survive bot restarts. On by default whenever TAK forwarding is on; set
  `TAK_EMERGENCY: "false"` to keep emergencies Mumble-only. Radios
  that never sent a position are skipped (no position to alert at).
- **Radios never vanish from the map**: when a radio goes silent
  (powered off, out of coverage), the server keeps re-broadcasting
  its last known position every 60 seconds, marked "last known" with
  a last-seen timestamp in the marker's remarks. The state is
  persisted in the `porto-tracks` volume, so it survives server
  restarts.
  Disable with `TAK_LAST_KNOWN: "false"`.
- **Track history**: every position is appended to
  `/app/tracks/<radio_id>.jsonl` in the dedicated `porto-tracks`
  volume (disable with
  `TRACK_HISTORY: "false"`). Export a day - or everything - as GPX:
  ```bash
  docker exec porto-watchdog python channel_bot.py --export-gpx radio01 2026-07-20 > trip.gpx
  ```
  Roughly 300 KB per radio per day at a 30s interval. Exports and
  trails are jitter-filtered by default; add `--raw` to `--export-gpx`
  for the unfiltered archive.
- **Trails on the map**: each radio drags a named line ("P1 trail")
  showing where it has been - the last `TAK_TRAIL_HOURS` (default 6)
  of its track, redrawn every 5 minutes so the map never accumulates
  a forever-trail. Trails are jitter-filtered: fixes with poor
  reported accuracy are dropped (`TRAIL_MAX_ACC`) and the line only
  gains a point once the radio actually moved `TRAIL_MIN_DIST` meters
  (default 20) - a parked radio shows a clean marker instead of a
  GPS-noise scribble, and its trail disappears entirely until it
  moves again. `TAK_TRAIL: "false"` disables. For longer history,
  ask for any day or date range on demand - **straight from TAK's
  chat**: send `trail P1`, `trail P1 yesterday`, or
  `trail P1 2026-07-18 2026-07-22` to All Chat Rooms (works in ATAK,
  WinTAK and WebTAK; by radio id, callsign or username,
  case-insensitive) and the bot draws the line and confirms in chat.
  It appears on every client as "P1 2026-07-18..2026-07-22" and
  auto-expires after an hour. The bot shows up in your contacts as
  `porto-watchdog` (TAK only delivers chat to announced contacts) -
  set `TAK_BOT_POSITION: "lat,lon"` to pin its marker at your
  server's location instead of 0,0. The same is available from the
  server CLI:
  ```bash
  docker exec porto-watchdog python channel_bot.py --publish-trail radio01 2026-07-20
  docker exec porto-watchdog python channel_bot.py --publish-trail radio01 2026-07-18 2026-07-22 --trail-ttl 120
  ```
- First GPS fix after power-on can take a couple of minutes cold.

## Channel Display on the Radio Screen (optional)

The TE300K's idle screen normally shows the date and time. With this
feature it shows what actually matters on a radio: `Channel: TAC 1`
in the center - or `Disconnected` when the server can't be reached or
the radio's user isn't on Mumble - plus the radio's identity
(`ID: P1`, fed by the server from your callsign config) bottom-right,
and the soft-key label bracketed as `[Settings]` so button
indications are visually distinct from status text.

How it works: the server replies to every packet a radio sends
(including a minutely `'H'` heartbeat from the local watchdog) with a
signed `'C'` packet carrying the radio's current channel name. The
local watchdog verifies it (HMAC + replay window - nobody else can
write to your screen) and stores it in
`/data/local/tmp/screenvars.txt` as `key=value` lines
(`channel=<name>`, `id=<callsign>`). The idle screen polls that file
every few seconds; a stale (>150s) or missing file, or an empty
`channel=`, means `Disconnected`.

The server and watchdog sides ship with this repo and are always on -
the reply simply goes unused if you skip the screen part. Radio side,
one-time:

1. Create the exchange file (the daemon can only write to existing
   files in `/data/local/tmp`, not create them):
   ```bash
   adb shell "touch /data/local/tmp/screenvars.txt && chmod 666 /data/local/tmp/screenvars.txt"
   ```
2. Patch the stock screen app. The firmware's `Te300k.apk` is signed
   with the public AOSP platform test keys - same story as
   [platform signing](#platform-signing-becoming-a-system-app) - so
   it can be decompiled with apktool, modified, re-signed with the
   same keys as `pttbridge.apk` (recipe in `pttbridge/README.md`),
   and installed with `adb install -r`. The changes:
   - `res/layout/activity_main.xml`: the `@string/ptt` TextView (the
     stray "PTT" label) becomes an `ID:` TextView (new `porto_id`
     resource id, registered in `values/ids.xml` + `public.xml`),
     and the Settings label becomes the literal `[Settings]`
   - `MainActivity$2.smali`: the clock tick sleep `0xea60` (60s)
     becomes `0xbb8` (3s)
   - `MainActivity$1.smali`: the clock case (`sswitch_0`) calls
     helpers that read `screenvars.txt` - `channel=` into the center
     text (fresh + non-empty -> `Channel: <name>`, else
     `Disconnected`) and `id=` into `ID: <callsign>` (falling back to
     knob.conf's `radio_id` before first server contact)

   The patched APK is the vendor's firmware app, so it is not
   distributed in this repo. Rollback at any time with
   `adb uninstall com.android.te300k` - that removes the update and
   restores the factory screen from `/system`.

Without the patch nothing changes on the radio - the feature is
inert.

## Adding More Radios

Repeat Step 2 with a different `radio_id` in `knob.conf`.

On the server, update the `RADIOS` env var and restart:

```
RADIOS="radio01=TE300K,radio02=TE300K-2,radio03=TE300K-3"
```

If you use per-radio secrets, add the new radio to `SECRETS` too.
For GPS tracking, additionally run the three "Radio side" commands
from [GPS Tracking](#gps-tracking-tak-integration) on the new radio,
and give it a friendly map name in `TAK_CALLSIGNS` if you use those.

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
| `CERT_DIR` | /app/certs | Certificate storage (bot's Mumble identity + enrolled TAK certs) |
| `TAK_HOST` | *(empty=disabled)* | TAK server hostname/IP for GPS forwarding |
| `TAK_PORT` | 8087 / 8089 with TLS | TAK streaming input port |
| `TAK_TLS` | false | Use TLS for the TAK connection (implied by enrollment) |
| `TAK_ENROLL_USER` | *(empty)* | Enrollment username - enables certificate self-enrollment |
| `TAK_ENROLL_PASS` | *(empty)* | Enrollment password |
| `TAK_ENROLL_PORT` | 8446 | TAK certificate-enrollment API port |
| `TAK_CA_FILE` | *(empty)* | CA cert for TLS (empty = no verification) |
| `TAK_CERT_FILE` | *(empty)* | Client cert PEM for TLS client auth |
| `TAK_KEY_FILE` | *(empty)* | Client key PEM for TLS client auth |
| `TAK_KEY_PASS` | *(empty)* | Password for an encrypted client key |
| `TAK_COT_TYPE` | a-f-G-U-C | CoT event type for radio markers |
| `TAK_STALE` | 300 | Seconds until a marker goes stale in ATAK |
| `TAK_EMERGENCY` | true | Raise a TAK 911 alert when a radio triggers an emergency |
| `TAK_EMERGENCY_STALE` | 300 | Seconds until an emergency alert clears in ATAK |
| `TAK_LAST_KNOWN` | true | Keep silent radios on the map at their last known position |
| `TAK_TRAIL` | true | Draw a rolling trail line per radio on the map |
| `TAK_TRAIL_HOURS` | 6 | Hours of track shown in the rolling trail |
| `TAK_BOT_POSITION` | *(empty = 0,0)* | "lat,lon" for the bot's own map marker (it must announce presence to receive chat commands) |
| `TRACK_HISTORY` | true | Log every position to a per-radio history file |
| `TRACK_DIR` | /app/tracks | Where position history is stored (`porto-tracks` volume) |
| `TRAIL_MIN_DIST` | 20 | Meters a radio must move before a trail gains a point (GPS jitter deadband, 0 = off) |
| `TRAIL_MAX_ACC` | 75 | Drop fixes with worse reported accuracy (meters) from trails/exports (0 = off) |
| `TAK_TEAM` | Cyan | ATAK team color |
| `TAK_ROLE` | Team Member | ATAK role shown on the marker |
| `TAK_CALLSIGNS` | *(empty)* | Per-radio callsigns: `radio01=Dad,radio02=Mom` |

## Security

All key events forwarded to the remote watchdog are authenticated.

| Layer | How |
|-------|-----|
| Authentication | Every UDP packet signed with HMAC-SHA256 |
| Position privacy | GPS coordinates encrypted per packet (encrypt-then-MAC, keys derived from the radio secret, random nonce) |
| Per-radio keys | Optional per-radio secrets via `SECRETS` env var |
| Replay protection | Packets expire after 30 seconds |
| IP allowlist | Optional `ALLOWED_IPS` env var |
| Per-radio identity | 8-char radio ID in every packet |
| TAK link | TLS with client-certificate auth (self-enrolled or manual) on the server-to-server hop |
| Screen feedback | Server-to-radio 'C' packets signed with the same per-radio secret and replay-windowed |

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
| `pttbridge/` | Source | Smali source for pttbridge.apk (build docs inside) |
| `pttbridge.apk` | Radio | Boot autostart + PTT socket bridge + Mumla auto-connect + GPS reader + self-healing watchdog |
| `mumla.apk` | Radio | Mumla v3.6.15 - open-source Mumble client ([GPL-3.0](https://github.com/quite/mumla)) |

Binaries are built automatically by CI - download `porto-watchdog` from
the [latest release](../../releases/latest) or the
[Actions](../../actions) tab (artifact: `porto-watchdog-arm`).

## Troubleshooting

- **Apps won't install** - `adb shell setprop persist.telo.install enable`
- **PTT not working** - `adb shell dumpsys activity services | grep pttbridge`. If not running: `adb shell am startservice -a com.pttbridge.START` (safe to repeat - since v1.2 the service is idempotent and only starts what is not already running)
- **Mumla or the daemon died in the field** - since pttbridge v1.2 they relaunch automatically within ~2 minutes (watch `adb shell logcat -d | grep heal:` to see it happen). During a Mumla outage the radio's screen shows `Disconnected`, then recovers on its own
- **Channel switch / emergency / ident not working** - check `knob.conf` on the radio: `host` must be reachable from the radio's network. Check UDP port 4378 is open. Check remote watchdog container logs: `docker logs porto-watchdog`
- **"HMAC verification failed"** - `secret` in `knob.conf` must match the server's `SECRET` or that radio's entry in `SECRETS`
- **"Replay rejected"** - radio clock is off. Check: `adb shell date`
- **"User not found"** - username in `RADIOS` must match Mumla's connection name (case-sensitive). Use `P*` wildcards if the name varies
- **Bot can't move users** - grant Move permission in Mumble ACL for the bot user
- **Auto-start not working after reboot** - check logcat: `adb shell logcat -d | grep -i pttbridge`. Also check the binary exists: `adb shell ls -la /data/local/tmp/porto-watchdog` and the symlink: `adb shell ls -la /data/local/tmp/ptt_bridge`
- **DNS not resolving on the radio** - check logcat: `adb shell logcat -d | grep porto-watchdog`. If you see "DNS not ready", the radio's WiFi may not be connected yet. The binary retries DNS on every keypress. You can also use an IP address directly in `knob.conf` to bypass DNS entirely
- **No TTS** - enable Text-to-Speech in Mumla settings on the radio
- **No GPS markers in ATAK** - check the chain step by step: `adb shell logcat -d | grep porto-watchdog` should show `LOC <lat> <lon>` lines when fixes flow. No lines? Check `loc.conf` exists, the location permission is granted (`adb shell dumpsys package com.pttbridge | grep ACCESS_FINE`), and GPS is enabled (`adb shell settings get secure location_providers_allowed`). Lines but no markers? Check the remote watchdog logs (`docker logs porto-watchdog`) for `TAK: connected` / `TAK: first position`, and that the TAK input you chose (stock TLS 8089, or STCP 8087) is reachable from the container
- **`TAK: enrollment failed` in the logs** - the enrollment user must exist on the TAK server and `TAK_ENROLL_PASS` must match. Remember TAK's password complexity rule (15+ chars, upper/lower/digit/special) when creating the user. Also check the container can reach the enrollment port: `TAK_ENROLL_PORT` (default 8446) is separate from the streaming input port
- **RSM PTT not working** - the daemon logs `rsm_ptt=/dev/input/event2` at startup (`adb shell logcat -d | grep porto-watchdog`). If it says `RSM PTT not available`, check the `ptt_device` line in `knob.conf`
- **Emergency doesn't appear on the TAK map** - the 911 alert is placed at the radio's last known position, which the bot keeps in memory: the radio must have reported at least one position since the bot last (re)started. Check the logs for `TAK: no position known for <radio>`. The Mumble voice alert is unaffected either way
- **Radio has no GPS fix indoors** - normal; cold start can take minutes and needs sky view. Test near a window or outside

## Roadmap

- **LED control** - adjust LED behavior based on external input and user preferences
- **More on the idle screen** - the channel display (above) covered the
  main wish; candidates for the remaining screen real estate: GPS fix
  status, server link quality, battery-friendly dark mode
