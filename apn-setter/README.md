# apn-setter.apk source

Smali source for `apn-setter.apk` (the repo root ships the built, signed APK).
A tiny, headless helper that writes a custom APN into Android's telephony
provider - used to fix radios whose built-in carrier APN is outdated and won't
roam abroad (data dies at a border even though the network registers fine). It
is driven by the watchdog daemon from `knob.conf` (see "Custom APN" in the main
README); the app itself hardcodes nothing.

| Class | Role |
|-------|------|
| `ApnSetterActivity` | Reads the APN from intent extras (`apn`, `name`, `mcc`, `mnc`, `numeric`, `protocol`, `roaming_protocol`, `type`), inserts it into `content://telephony/carriers`, makes it the preferred APN, then **disables every other APN** (`carrier_enabled=0 WHERE _id != <ours>`) so the firmware can't re-select a stale one - you never have to name it. Idempotent (dedups by apn+numeric), then finishes - no UI. |
| `VerifyActivity` | Debug only: logs the current preferred APN (name / apn / protocol / roaming_protocol) to logcat tag `ApnVerify`. |

## Why platform-signed

Writing the telephony `carriers` provider needs `WRITE_APN_SETTINGS`, which is
`signatureOrSystem` on Android 6 - so `adb`/`content` can't do it, and neither
can a normal app. Signing the APK with the public AOSP platform key (same key as
`pttbridge`) grants it at install, no prompt and no root. On the TE300K the stock
APN editor is also OEM-locked ("not available for this user"), so this is the
only way to change the APN on the device at all.

## Build

Requires Java and [apktool](https://apktool.org/):

```bash
apktool b apn-setter -o apn-setter-unsigned.apk
```

## Sign with the AOSP platform keys

Same keys and flow as `pttbridge` (see `pttbridge/README.md`). Convert the
platform key pair to a PKCS12 keystore once:

```bash
openssl pkcs8 -inform DER -nocrypt -in platform.pk8 -out platform-key.pem
openssl pkcs12 -export -inkey platform-key.pem -in platform.x509.pem \
    -name platform -password pass:android -out platform.p12
```

Then sign (v1/JAR signature - exactly what Android 6.0 expects):

```bash
jarsigner -keystore platform.p12 -storetype PKCS12 -storepass android \
    -sigalg SHA256withRSA -digestalg SHA-256 apn-setter-unsigned.apk platform
mv apn-setter-unsigned.apk apn-setter.apk
```

The AOSP platform cert is self-signed with MD5, which recent JDKs reject by
default. If jarsigner errors with "certificate ... MD5withRSA ... is disabled",
re-run it with an override that clears the disabled-algorithm lists:

```bash
printf 'jdk.jar.disabledAlgorithms=\njdk.certpath.disabledAlgorithms=\n' > nomd5.props
jarsigner -J-Djava.security.properties=nomd5.props \
    -keystore platform.p12 -storetype PKCS12 -storepass android \
    -sigalg SHA256withRSA -digestalg SHA-256 apn-setter-unsigned.apk platform
```

## Manual test

```bash
adb install -r apn-setter.apk
adb shell am start -n com.porto.apnsetter/.ApnSetterActivity \
    --es apn internet --es mcc 204 --es mnc 08 --es numeric 20408 \
    --es protocol IPV4V6 --es roaming_protocol IP --es type default,supl
# apply on the next data reconnect, then confirm:
adb shell "svc data disable; svc data enable"
adb shell "dumpsys connectivity | grep -o 'extra: [^,]*'"   # -> extra: internet
```

In normal operation you never run this by hand - the watchdog daemon launches it
on every boot with the values from `knob.conf`.
