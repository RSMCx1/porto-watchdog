package com.pttbridge;

import java.io.BufferedReader;
import java.io.FileReader;

/**
 * Single-value lookups in the daemon's config file.
 *
 * knob.conf is the one place a radio is described, and the app has to agree with
 * the daemon about what kind of radio it is running on. Rather than introduce a
 * second config that could drift out of step, both read the same file:
 * input_source selects the input backend in the daemon and, through here, the
 * matching behaviour in the app.
 *
 * Classes that need several values at once (KeyService, Tone) keep their own
 * single-pass reader. This is for the one-off questions.
 */
public final class Conf {

    private static final String CONF = "/data/local/tmp/knob.conf";

    private Conf() { }

    /**
     * True when this radio delivers its buttons as framework KeyEvents rather
     * than through /dev/input.
     *
     * A missing or unreadable config reads as evdev, because that is what every
     * radio deployed before this option existed does, and a config the app
     * cannot read must never change how one of those behaves.
     */
    public static boolean keyeventPath() {
        return "keyevent".equals(get("input_source", "evdev"));
    }

    /** The value for key, or dflt when the file or the key is absent. */
    public static String get(String key, String dflt) {
        BufferedReader r = null;
        try {
            r = new BufferedReader(new FileReader(CONF));
            String line;
            while ((line = r.readLine()) != null) {
                line = line.trim();
                int eq = line.indexOf('=');
                if (line.length() == 0 || line.charAt(0) == '#' || eq <= 0) {
                    continue;
                }
                if (key.equals(line.substring(0, eq).trim())) {
                    return line.substring(eq + 1).trim();
                }
            }
        } catch (Exception e) {
            // Fall through to the default.
        } finally {
            if (r != null) {
                try {
                    r.close();
                } catch (Exception ignored) {
                }
            }
        }
        return dflt;
    }
}
