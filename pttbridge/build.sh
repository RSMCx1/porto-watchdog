#!/bin/sh
# Build and sign pttbridge.apk.
#
# This is an apktool project: the eight original classes exist only as smali and
# are edited as smali. The classes added for multi-radio support are written in
# Java instead - they are long enough that hand-written smali would not be
# reviewable - so the build compiles them and merges the generated smali in
# before apktool assembles everything.
#
#   src/*.java --javac--> .class --d8--> .dex --baksmali--> smali/ --apktool--> apk
#
# Nothing here is radio-specific. One APK serves every radio; which behaviour it
# takes is decided at runtime by input_source in knob.conf.
#
# Requirements (set the paths below or export them):
#   ANDROID_JAR  android.jar from API 22. The radios run 5.1.1/6.0.1, and
#                compiling against a newer one risks linking against methods
#                that are not there.
#   D8           d8 (or r8.jar's D8 entry point) from Android build-tools.
#   BAKSMALI     baksmali jar.
#   APKTOOL      apktool jar, 2.9 or newer.
#   PLATFORM_KEY platform.pk8 / platform.x509.pem for the target radio.
#   CC           ARM cross compiler, only needed for the packaged daemon.
#
# The platform key matters: DIAGNOSTIC and INJECT_EVENTS are signature-level, so
# an APK signed with anything else installs but silently cannot do its job. Both
# radios tested so far ship firmware signed with the public AOSP test key, so the
# AOSP platform key works - confirm per radio before assuming it (see README).
set -e

here=$(cd "$(dirname "$0")" && pwd)
cd "$here"

ANDROID_JAR=${ANDROID_JAR:?set ANDROID_JAR to an API 22 android.jar}
D8=${D8:?set D8 to the d8 executable or jar}
BAKSMALI=${BAKSMALI:?set BAKSMALI to the baksmali jar}
APKTOOL=${APKTOOL:?set APKTOOL to the apktool jar}
PLATFORM_KEY=${PLATFORM_KEY:-}
CC=${CC:-arm-linux-gnueabihf-gcc}

out=build
rm -rf "$out"
mkdir -p "$out/classes" "$out/dex" "$out/smali"

echo "==> javac (source/target 8, bootclasspath API 22)"
javac -source 8 -target 8 -bootclasspath "$ANDROID_JAR" -nowarn \
      -d "$out/classes" src/com/pttbridge/*.java

echo "==> d8 --min-api 22"
case "$D8" in
  *.jar) java -cp "$D8" com.android.tools.r8.D8 --min-api 22 --output "$out/dex" \
              --lib "$ANDROID_JAR" $(find "$out/classes" -name '*.class') ;;
  *)     "$D8" --min-api 22 --output "$out/dex" --lib "$ANDROID_JAR" \
              $(find "$out/classes" -name '*.class') ;;
esac

echo "==> baksmali, then merge into smali/"
java -jar "$BAKSMALI" d "$out/dex/classes.dex" -o "$out/smali"
# Only the compiled classes are in this dex, so this cannot clobber the eight
# hand-written ones. Copying rather than moving keeps build/ inspectable.
cp "$out/smali"/com/pttbridge/*.smali smali/com/pttbridge/
echo "    merged: $(ls "$out/smali"/com/pttbridge/*.smali | wc -l) generated classes"

# The daemon ships inside the APK because a radio may refuse to execute it from
# anywhere else - see Paths.java. Radios on the evdev path ignore this copy and
# keep running the one in /data/local/tmp, so a missing cross compiler is not
# fatal for them.
if command -v "$CC" >/dev/null 2>&1; then
    echo "==> daemon -> lib/armeabi-v7a/libportowatchdog.so"
    mkdir -p lib/armeabi-v7a
    "$CC" -static -Wall -Wextra -O2 -o lib/armeabi-v7a/libportowatchdog.so ../knob_reader.c
else
    echo "==> skipping packaged daemon ($CC not found)"
fi

echo "==> apktool b"
java -jar "$APKTOOL" b . -o "$out/pttbridge-unsigned.apk"

if [ -n "$PLATFORM_KEY" ]; then
    echo "==> sign with platform key"
    # apksigner is preferred; jarsigner also works on these API levels.
    apksigner sign --key "$PLATFORM_KEY.pk8" --cert "$PLATFORM_KEY.x509.pem" \
        --out "$out/pttbridge.apk" "$out/pttbridge-unsigned.apk"
    echo "    signed: $out/pttbridge.apk"
else
    echo "    PLATFORM_KEY unset - leaving $out/pttbridge-unsigned.apk unsigned"
fi

echo
echo "Install, then for a keyevent radio enable the accessibility service:"
echo "  adb install -r $out/pttbridge.apk"
echo "  adb shell settings put secure enabled_accessibility_services com.pttbridge/com.pttbridge.KeyService"
echo "  adb shell settings put secure accessibility_enabled 1"
echo "Installing again clears those two settings - re-apply them every time."
