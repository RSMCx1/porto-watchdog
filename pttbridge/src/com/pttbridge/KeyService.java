package com.pttbridge;

import android.accessibilityservice.AccessibilityService;
import android.content.Intent;
import android.net.LocalSocket;
import android.net.LocalSocketAddress;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.PowerManager;
import android.util.Log;
import android.view.KeyEvent;
import android.view.accessibility.AccessibilityEvent;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.OutputStream;

/**
 * Hardware buttons as framework KeyEvents, for radios where SELinux forbids
 * an app uid from reading /dev/input (YiNiTone B5 / Anysecu T56, UNIPRO L809).
 *
 * Opt-in and inert by default: an AccessibilityService that is not listed in
 * Settings.Secure.enabled_accessibility_services is never bound, so radios on
 * the evdev path (TE300K) are untouched even though they ship the same APK.
 *
 * PTT never leaves the app - it goes straight to Mumla, so keying up does not
 * depend on the native daemon being alive. Every other button is forwarded as
 * a raw edge to the daemon over abstract socket @porto_key; the daemon keeps
 * ownership of debounce, emergency_hold_ms, HMAC signing and UDP.
 */
public class KeyService extends AccessibilityService {

    private static final String TAG = "pttbridge";
    private static final String CONF = "/data/local/tmp/knob.conf";
    private static final String KEY_SOCKET = "porto_key";

    /* Defaults are the B5 / L809 codes: this service only ever runs on radios
     * that were deliberately switched to the keyevent path. Override in
     * knob.conf with keyevent_ptt= etc. */
    private int mPtt = 261;         // DTT_PTT
    private int mIdent = 21;        // DPAD_LEFT  (FN2)
    private int mEmerg = 22;        // DPAD_RIGHT (FN1)
    private int mNext = 260;        // DTT_SOS    (channel up)
    private int mPrev = 266;        // FN3        (channel down)
    private boolean mConsume = true;
    private boolean mKeepInteractive = false;

    private boolean mPttDown = false;
    private Handler mIo;
    private PowerManager.WakeLock mWake;

    @Override
    public void onCreate() {
        super.onCreate();
        HandlerThread t = new HandlerThread("porto-key-io");
        t.start();
        mIo = new Handler(t.getLooper());
    }

    @Override
    protected void onServiceConnected() {
        loadConfig();
        // Belt and braces: BootReceiver normally starts it, but the service may
        // have been killed, and the daemon is what turns @porto_key into UDP.
        try {
            Intent i = new Intent("com.pttbridge.START");
            i.setPackage("com.pttbridge");
            startService(i);
        } catch (Throwable t) {
            Log.w(TAG, "startService: " + t);
        }
        if (mKeepInteractive) {
            acquireWake();
        }
        Log.i(TAG, "KeyService connected: ptt=" + mPtt + " ident=" + mIdent
                + " emerg=" + mEmerg + " next=" + mNext + " prev=" + mPrev
                + " consume=" + mConsume + " keep_interactive=" + mKeepInteractive);
    }

    @Override
    public void onDestroy() {
        releaseWake();
        super.onDestroy();
    }

    @Override
    protected boolean onKeyEvent(KeyEvent event) {
        final int code = event.getKeyCode();
        final boolean down = event.getAction() == KeyEvent.ACTION_DOWN;

        if (code == mPtt) {
            // PTT auto-repeats while held; only the edges matter.
            if (down) {
                if (!mPttDown) {
                    mPttDown = true;
                    Talk.send(this, "on");
                    Log.i(TAG, "PTT DOWN");
                }
            } else {
                if (mPttDown) {
                    mPttDown = false;
                    Talk.send(this, "off");
                    Log.i(TAG, "PTT UP");
                }
            }
            return true;   // always consumed, never navigates the UI
        }

        String cmd = null;
        if (code == mIdent) {
            cmd = "IDENT";
        } else if (code == mEmerg) {
            cmd = "EMERGENCY";
        } else if (code == mNext) {
            cmd = "NEXT";
        } else if (code == mPrev) {
            cmd = "PREV";
        }
        if (cmd == null) {
            return false;
        }
        if (down && event.getRepeatCount() != 0) {
            return mConsume;   // swallow the repeat storm, do not re-fire
        }
        // Both edges go to the daemon: EMERGENCY's hold gate is measured there.
        post(cmd + (down ? " 1\n" : " 0\n"));
        return mConsume;
    }

    @Override
    public void onAccessibilityEvent(AccessibilityEvent event) {
    }

    @Override
    public void onInterrupt() {
    }

    /* ---- daemon socket ---- */

    private void post(final String line) {
        // Never block the accessibility callback: the framework hands the key
        // to the foreground app if we do not answer within its timeout.
        mIo.post(new Runnable() {
            @Override
            public void run() {
                write(line);
            }
        });
    }

    private void write(String line) {
        LocalSocket s = null;
        try {
            s = new LocalSocket();
            s.connect(new LocalSocketAddress(KEY_SOCKET,
                    LocalSocketAddress.Namespace.ABSTRACT));
            OutputStream os = s.getOutputStream();
            os.write(line.getBytes("UTF-8"));
            os.flush();
            Log.i(TAG, "key -> daemon: " + line.trim());
        } catch (Throwable t) {
            Log.w(TAG, "key socket: " + t);
        } finally {
            if (s != null) {
                try {
                    s.close();
                } catch (Throwable ignored) {
                }
            }
        }
    }

    /* ---- config ---- */

    private void loadConfig() {
        BufferedReader r = null;
        try {
            r = new BufferedReader(new FileReader(CONF));
            String ln;
            while ((ln = r.readLine()) != null) {
                ln = ln.trim();
                int eq = ln.indexOf('=');
                if (ln.length() == 0 || ln.charAt(0) == '#' || eq <= 0) {
                    continue;
                }
                String k = ln.substring(0, eq).trim();
                String v = ln.substring(eq + 1).trim();
                if ("keyevent_ptt".equals(k)) {
                    mPtt = num(v, mPtt);
                } else if ("keyevent_ident".equals(k)) {
                    mIdent = num(v, mIdent);
                } else if ("keyevent_emergency".equals(k)) {
                    mEmerg = num(v, mEmerg);
                } else if ("keyevent_chan_next".equals(k)) {
                    mNext = num(v, mNext);
                } else if ("keyevent_chan_prev".equals(k)) {
                    mPrev = num(v, mPrev);
                } else if ("keyevent_consume".equals(k)) {
                    mConsume = bool(v, mConsume);
                } else if ("keep_interactive".equals(k)) {
                    mKeepInteractive = bool(v, mKeepInteractive);
                }
            }
        } catch (Throwable t) {
            Log.w(TAG, "config: " + t + " (using built-in B5 defaults)");
        } finally {
            if (r != null) {
                try {
                    r.close();
                } catch (Throwable ignored) {
                }
            }
        }
    }

    private static int num(String v, int dflt) {
        try {
            return Integer.parseInt(v);
        } catch (Throwable t) {
            return dflt;
        }
    }

    private static boolean bool(String v, boolean dflt) {
        if ("true".equals(v) || "1".equals(v) || "yes".equals(v)) {
            return true;
        }
        if ("false".equals(v) || "0".equals(v) || "no".equals(v)) {
            return false;
        }
        return dflt;
    }

    /* ---- screen-off mitigation ----
     * On API 22 PhoneWindowManager drops non-media keys while the display is
     * off, so nothing above the policy - including this service - sees them.
     * keep_interactive=true holds a SCREEN_DIM_WAKE_LOCK so the device stays
     * interactive and the keys keep arriving. Costs battery; intended for
     * permanently powered installs. */
    private void acquireWake() {
        try {
            PowerManager pm = (PowerManager) getSystemService(POWER_SERVICE);
            mWake = pm.newWakeLock(PowerManager.SCREEN_DIM_WAKE_LOCK
                    | PowerManager.ON_AFTER_RELEASE, "porto:keys");
            mWake.setReferenceCounted(false);
            mWake.acquire();
            Log.i(TAG, "SCREEN_DIM_WAKE_LOCK held (keep_interactive=true)");
        } catch (Throwable t) {
            Log.w(TAG, "wakelock: " + t);
        }
    }

    private void releaseWake() {
        try {
            if (mWake != null && mWake.isHeld()) {
                mWake.release();
            }
        } catch (Throwable ignored) {
        }
        mWake = null;
    }
}
