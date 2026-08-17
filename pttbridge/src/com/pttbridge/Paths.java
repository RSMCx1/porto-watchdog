package com.pttbridge;

import java.io.File;

/**
 * Where the porto-watchdog daemon binary lives, resolved at runtime.
 *
 * The daemon used to sit in /data/local/tmp, pushed there by adb. That works on
 * the TE300K but not on every radio: /data/local/tmp is labelled
 * shell_data_file, and SELinux grants no app domain execute on it. On the
 * YiNiTone B5 the launch dies with
 *
 *   avc: denied { execute } for name="ptt_bridge"
 *        scontext=u:r:platform_app:s0 tcontext=u:object_r:shell_data_file:s0
 *
 * The app's own data dir is no better - appdomain gets read/write on
 * app_data_file but not execute (only untrusted_app does, which we are not).
 * The one directory an app may execute from is the APK's extracted native
 * library dir, which is apk_data_file:
 *
 *   allow appdomain apk_data_file:file { execute execute_no_trans ... };
 *
 * So the daemon ships inside the APK as lib/armeabi-v7a/libportowatchdog.so and
 * Android extracts it for us. The catch is the directory carries an install
 * generation suffix (com.pttbridge-1, -2, ...) that changes on every reinstall,
 * so it cannot be hardcoded. A glob would work for the shell exec but not for
 * the /proc cmdline comparison, which is an exact String.equals - both sides
 * must agree on one resolved path, which is what this returns.
 */
public final class Paths {

    private static final String LIB = "libportowatchdog.so";

    /** Legacy location, still correct on radios that allow exec from there. */
    private static final String LEGACY = "/data/local/tmp/ptt_bridge";

    private static String cached;

    private Paths() { }

    /**
     * Absolute path to the daemon, or the legacy path if no packaged copy is
     * found. Cached: the answer cannot change while the process lives, and both
     * the launcher and the /proc scan must see the same string.
     */
    /*
     * Only radios on the keyevent path use the packaged copy.
     *
     * An evdev radio already runs a daemon from LEGACY, started before this app
     * shipped a binary of its own and still the path recorded in /proc.
     * Preferring the packaged one there would make HealthRunner.isRunning()'s
     * exact String.equals miss the live process, so a second daemon would start
     * and both would bind the same socket and sign for the same radio_id.
     * input_source is the same switch the daemon reads, so the two cannot
     * disagree about which radio this is.
     */
    public static synchronized String daemon() {
        if (cached != null) {
            return cached;
        }
        String found = Conf.keyeventPath() ? locate() : null;
        cached = (found != null) ? found : LEGACY;
        return cached;
    }

    /**
     * The sh -c command that starts the daemon, with output appended to a log
     * in the app's data dir.
     *
     * logwrapper is kept on the evdev path and dropped on the keyevent path. It
     * wants a pty, and on radios whose policy denies platform_app access to
     * devpts it dies before the daemon is ever reached:
     *
     *   avc: denied { open } for path="/dev/pts/1"
     *        scontext=u:r:platform_app:s0 tcontext=u:object_r:devpts:s0
     *
     * Redirecting to a file gets the same diagnostics with no pty involved.
     */
    public static String launchCommand() {
        if (!Conf.keyeventPath()) {
            // Unchanged for radios that worked before any of this existed.
            // logwrapper puts the daemon's output into logcat, which is where the
            // README's troubleshooting steps tell people to look for it.
            return "exec /system/bin/logwrapper " + daemon();
        }
        return "exec " + daemon() + " >>/data/data/com.pttbridge/ptt.log 2>&1";
    }

    /** ABI subdirectory names the extractor may have used. */
    private static final String[] ABIS = { "arm", "armeabi-v7a", "armeabi", "arm64", "arm64-v8a" };

    /**
     * Probe candidate paths rather than listing directories.
     *
     * /data/app is mode drwxrwx--x: an app is not the owner or in the group, so
     * it gets traverse but NOT read. listFiles() therefore returns null and any
     * directory-walking approach silently finds nothing - note this is a plain
     * Unix permission problem, not SELinux, which does allow appdomain
     * apk_data_file:dir read. Traversal is enough to stat a path we name
     * outright, so construct the candidates instead.
     *
     * The install generation suffix increments on reinstall and is not exposed
     * anywhere an app can read without a Context, so walk a sensible range.
     */
    private static String locate() {
        for (int gen = -1; gen <= 32; gen++) {
            String dir = (gen < 0) ? "/data/app/com.pttbridge"
                                   : "/data/app/com.pttbridge-" + gen;
            for (String abi : ABIS) {
                File candidate = new File(dir + "/lib/" + abi + "/" + LIB);
                if (candidate.canExecute()) {
                    return candidate.getAbsolutePath();
                }
            }
        }
        return null;
    }
}
