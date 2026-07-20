# pttbridge.apk source

Smali source for `pttbridge.apk` (the repo root ships the built, signed APK).
The app is deliberately tiny - no resources, no layouts, just a manifest and
a handful of classes:

| Class | Role |
|-------|------|
| `BootReceiver` | `BOOT_COMPLETED` -> starts `BridgeService` |
| `BridgeService` | Launches the `porto-watchdog` daemon, launches Mumla, injects the auto-connect keypress, starts the threads below |
| `BridgeService$SocketThread` | Serves abstract local socket `ptt_bridge`; byte `'1'`/`'0'` -> Mumla TALK on/off broadcast |
| `BridgeService$HomeRunner` | 15s after boot, returns to the home screen |
| `HealthRunner` | Self-heal watchdog: scans `/proc` every minute and relaunches Mumla (incl. auto-connect) or the daemon if either died |
| `LocRunner` | Reads `/data/local/tmp/loc.conf` (GPS interval in seconds, opt-in); registers a GPS listener |
| `LocListener` | Each GPS fix -> `"lat lon alt speed bearing accuracy\n"` -> `LocSender` |
| `LocSender` | Writes the fix line to the daemon's abstract local socket `porto_loc` |

## Build

Requires Java and [apktool](https://apktool.org/):

```bash
apktool b pttbridge -o pttbridge-unsigned.apk
```

## Sign with the AOSP platform keys

The TE300K firmware is signed with the public AOSP test platform keys, so the
APK must be too (that's what makes `DIAGNOSTIC` work - see the main README).
Get `platform.pk8` / `platform.x509.pem` from the AOSP source tree
(`build/target/product/security/`), convert once to a PKCS12 keystore:

```bash
openssl pkcs8 -inform DER -nocrypt -in platform.pk8 -out platform-key.pem
openssl pkcs12 -export -inkey platform-key.pem -in platform.x509.pem \
    -name platform -password pass:android -out platform.p12
```

Then sign (v1/JAR signature - exactly what Android 6.0 expects):

```bash
jarsigner -keystore platform.p12 -storetype PKCS12 -storepass android \
    -sigalg SHA256withRSA -digestalg SHA-256 pttbridge-unsigned.apk platform
mv pttbridge-unsigned.apk pttbridge.apk
```

Install with `adb install -r pttbridge.apk` (upgrades keep the granted
permissions and boot-start behavior).
