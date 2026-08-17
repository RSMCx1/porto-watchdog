# pttbridge.apk source

Source for `pttbridge.apk`. One APK serves every radio; which behaviour it takes
is decided at runtime by `input_source` in `knob.conf`.

The eight original classes exist only as smali and are edited as smali. The
classes added for multi-radio support are written in Java under `src/`, because
at their size hand-written smali would not be reviewable - `build.sh` compiles
them and merges the generated smali before apktool assembles the APK.

> **The APK committed at the repo root is the evdev build and does not contain
> the classes below.** It is the binary the existing fleet runs, left untouched
> on purpose. To get the multi-radio behaviour, build and sign your own with
> `build.sh` and test it on the radio before rolling it out.

## Classes

| Class | Source | Role |
|-------|--------|------|
| `BootReceiver` | smali | `BOOT_COMPLETED` -> starts `BridgeService` |
| `BridgeService` | smali | Launches the `porto-watchdog` daemon and Mumla, fires the auto-connect keypress, starts the threads below |
| `BridgeService$SocketThread` | smali | Serves abstract local socket `ptt_bridge`; byte `'1'`/`'0'` -> Mumla TALK on/off broadcast |
| `BridgeService$HomeRunner` | smali | 15s after boot, returns to the home screen |
| `HealthRunner` | smali | Self-heal watchdog: scans `/proc` every minute and relaunches Mumla (incl. auto-connect) or the daemon if either died |
| `LocRunner` | smali | Reads `/data/local/tmp/loc.conf` (GPS interval in seconds, opt-in); registers a GPS listener |
| `LocListener` | smali | Each GPS fix -> `"lat lon alt speed bearing accuracy\n"` -> `LocSender` |
| `LocSender` | smali | Writes the fix line to the daemon's abstract local socket `porto_loc` |
| `KeyService` | Java | Accessibility service: hardware buttons as framework `KeyEvent`s, forwarded to the daemon over `@porto_key`. Inert unless enabled in settings |
| `Talk` | Java | The one place that tells Mumla to key up / key down on the keyevent path |
| `Tone` | Java | PTT confirmation chirps, synthesised to the cache and played through SoundPool. Off unless `ptt_tone=true` |
| `Paths` | Java | Resolves where the daemon lives - `/data/local/tmp` or the copy packaged in the APK |
| `Inject` | Java | `InputManager.injectInputEvent` auto-connect, for radios where `sendevent` is blocked |
| `ScreenActivity` | Java | Bare idle display: channel and radio ID, no title bar, no settings |
| `Conf` | Java | Single-value lookups in `knob.conf`, so the app and the daemon agree on the radio |

## Build

`build.sh` runs the whole pipeline:

```
src/*.java --javac--> .class --d8--> .dex --baksmali--> smali/ --apktool--> apk
```

```bash
ANDROID_JAR=/path/to/android-22/android.jar \
D8=/path/to/d8 \
BAKSMALI=/path/to/baksmali.jar \
APKTOOL=/path/to/apktool.jar \
PLATFORM_KEY=/path/to/platform \
./build.sh
```

Compile against an **API 22** `android.jar`: the radios run 5.1.1 and 6.0.1, and
a newer one risks linking against methods that are not there. `apktool.yml` pins
`minSdkVersion: 22` with `targetSdkVersion: 23` - that pair is deliberate.
`minSdk 23` is refused on an API 22 radio (`INSTALL_FAILED_OLDER_SDK`), and
dropping `targetSdk` to 22 is refused on the API 23 radio
(`INSTALL_FAILED_PERMISSION_MODEL_DOWNGRADE`) as well as turning the location
permission back into an install-time grant.

If you have only changed smali, apktool alone is still enough:

```bash
apktool b pttbridge -o pttbridge-unsigned.apk
```

## Sign with the AOSP platform keys

Both radios tested so far ship firmware signed with the public AOSP test platform
keys, so the APK must be too - that is what makes `DIAGNOSTIC` and
`INJECT_EVENTS` work (see the main README). Confirm it per radio before assuming
it. Get `platform.pk8` / `platform.x509.pem` from the AOSP source tree
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

## Enabling the keyevent path

`KeyService` is an accessibility service, so it does nothing until it is switched
on. Nothing else needs to change on radios that stay on the evdev path.

```bash
adb shell settings put secure enabled_accessibility_services com.pttbridge/com.pttbridge.KeyService
adb shell settings put secure accessibility_enabled 1
```

Installing the APK again clears both settings - re-apply them after every
install, or the buttons go quiet with no other symptom. The same is true after
`am force-stop com.pttbridge`.
