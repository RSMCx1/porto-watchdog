package com.pttbridge;

import android.content.Context;
import android.content.Intent;

import java.io.BufferedReader;
import java.io.FileReader;

/**
 * The one place that tells Mumla to key up / key down.
 *
 * Called from KeyService, i.e. by radios on the keyevent path (B5 / L809),
 * where the framework hands us the button and no daemon sits in the PTT path.
 *
 * Radios on the evdev path (TE300K) still broadcast to Mumla directly from
 * BridgeService$SocketThread, where a byte '1'/'0' arrives from the native
 * daemon on abstract socket @ptt_bridge. That path is deliberately left alone:
 * the confirmation tone is the only reason it would need to come through here,
 * and the tone cannot be made to work on that radio anyway - see Tone.
 */
public final class Talk {
    public static final String ACTION = "se.lublin.mumla.action.TALK";
    public static final String MUMLA = "se.lublin.mumla";
    private static final String SCREENVARS = "/data/local/tmp/screenvars.txt";

    /** Whether the press that opened this transmission had a server behind it. */
    private static boolean sOpenedConnected = false;

    private Talk() {
    }

    public static void send(Context ctx, String status) {
        boolean on = "on".equals(status);
        if (on) {
            // A confirmation chirp while disconnected tells the operator they
            // were heard when nothing left the radio. Distinguish the two.
            sOpenedConnected = connected();
            if (sOpenedConnected) {
                Tone.press(ctx);
            } else {
                Tone.error(ctx);
            }
        } else if (sOpenedConnected) {
            Tone.release(ctx);
        }

        Intent i = new Intent(ACTION);
        i.setPackage(MUMLA);
        i.putExtra("status", status);
        ctx.sendBroadcast(i);
    }

    /**
     * Are we actually on a channel?
     *
     * The daemon rewrites screenvars.txt from the server's 'C' packets, so this
     * is the same fact the idle screen displays - the tone and the screen can
     * never contradict each other. Read per press: it is two short lines in
     * page cache, and a cached "connected" would defeat the point.
     *
     * Note the known gap: the daemon does not blank this on link loss, so a
     * radio that loses coverage mid-shift still reads as connected until the
     * next 'C' packet. Fixing that belongs in knob_reader.c, not here.
     */
    private static boolean connected() {
        BufferedReader r = null;
        try {
            r = new BufferedReader(new FileReader(SCREENVARS));
            String line;
            while ((line = r.readLine()) != null) {
                if (line.startsWith("channel=")) {
                    return line.substring(8).trim().length() > 0;
                }
            }
        } catch (Exception e) {
            // No file means nothing has ever connected.
        } finally {
            if (r != null) {
                try {
                    r.close();
                } catch (Exception ignored) {
                }
            }
        }
        return false;
    }
}
