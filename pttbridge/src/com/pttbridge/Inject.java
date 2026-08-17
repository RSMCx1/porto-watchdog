package com.pttbridge;

import android.os.SystemClock;
import android.view.KeyEvent;

import java.lang.reflect.Method;

/**
 * Inject a key event without touching /dev/input.
 *
 * Mumla does not connect on launch - it only restores a connection that was
 * already live. So something has to press ENTER on its server list after every
 * boot, which is what the TE300K does by shelling out to sendevent.
 *
 * That approach is dead on radios like the YiNiTone B5:
 *
 *   avc: denied { search } for name="input"
 *        scontext=u:r:platform_app:s0 tcontext=u:object_r:input_device:s0
 *
 * and gpio-keys there does not even declare KEY_ENTER, so the scancode would
 * have been dropped by the input core regardless.
 *
 * InputManager.injectInputEvent goes through the framework instead of the
 * kernel device nodes, so neither problem applies. It needs
 * android.permission.INJECT_EVENTS, which is signature-level - available to us
 * only because pttbridge is signed with the platform key, the same reason
 * DIAGNOSTIC works. The method is @hide, hence reflection; on API 22 there are
 * no hidden-API restrictions, so this is stable.
 */
public final class Inject {

    /** InputManager.INJECT_INPUT_EVENT_MODE_WAIT_FOR_FINISH */
    private static final int MODE_WAIT_FOR_FINISH = 2;

    private Inject() { }

    /**
     * Press and release a key. Returns false if the framework refused it, which
     * in practice means INJECT_EVENTS was not granted - i.e. the APK is not
     * signed with this device's platform key.
     */
    public static boolean key(int keyCode) {
        try {
            Class<?> imClass = Class.forName("android.hardware.input.InputManager");
            Method getInstance = imClass.getMethod("getInstance");
            Object im = getInstance.invoke(null);
            Method inject = imClass.getMethod("injectInputEvent", android.view.InputEvent.class, int.class);

            long now = SystemClock.uptimeMillis();
            KeyEvent down = new KeyEvent(now, now, KeyEvent.ACTION_DOWN, keyCode, 0);
            KeyEvent up = new KeyEvent(now, now, KeyEvent.ACTION_UP, keyCode, 0);

            Object a = inject.invoke(im, down, MODE_WAIT_FOR_FINISH);
            Object b = inject.invoke(im, up, MODE_WAIT_FOR_FINISH);
            return Boolean.TRUE.equals(a) && Boolean.TRUE.equals(b);
        } catch (Throwable t) {
            android.util.Log.w("pttbridge", "inject " + keyCode + " failed: " + t);
            return false;
        }
    }

    /**
     * Fire the auto-connect press on a background thread.
     *
     * No-arg so the call site is a single smali instruction. The delay mirrors
     * the "sleep 8" the shell version used: Mumla has to be drawn and focused
     * before a key means anything, and boot is the slowest the radio ever is.
     */
    public static void autoConnect() {
        if (!Conf.keyeventPath()) {
            // evdev radios auto-connect with the sendevent sequence that
            // BridgeService already runs, which is known good there. This call
            // site is additive rather than a replacement, so the two would
            // otherwise both press ENTER.
            return;
        }
        new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    Thread.sleep(8000);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return;
                }
                connectMumla(2, 1500);
            }
        }, "porto-autoconnect").start();
    }

    /**
     * The auto-connect press: ENTER on Mumla's server list.
     *
     * Called on a delay after Mumla is launched, because the list has to be on
     * screen and focused first - injecting into a half-drawn activity does
     * nothing. Retries a few times rather than assuming one press lands, since
     * launch time varies with how loaded the radio is at boot.
     */
    public static void connectMumla(int attempts, long gapMs) {
        for (int i = 0; i < attempts; i++) {
            boolean ok = key(KeyEvent.KEYCODE_ENTER);
            android.util.Log.i("pttbridge", "auto-connect ENTER attempt " + (i + 1) + " -> " + ok);
            if (!ok) {
                return;   // permission missing; retrying will not help
            }
            try {
                Thread.sleep(gapMs);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
        }
    }
}
