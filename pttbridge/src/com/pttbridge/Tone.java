package com.pttbridge;

import android.content.Context;
import android.media.AudioManager;
import android.media.SoundPool;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;

/**
 * The PTT confirmation tones: a rising two-tone chirp on press, falling on
 * release, and a flat low tone when the radio is not connected.
 *
 * Built on SoundPool, after AudioTrack proved to be the wrong tool three times
 * over on a TE300K:
 *
 *   - MODE_STATIC with a guessed sleep before stop() truncated the tone
 *   - a fresh track per press cost so much creation latency that an 80ms tone
 *     was over before output began - nothing was heard unless PTT was spammed,
 *     which warmed the path
 *   - a persistent MODE_STREAM track buffered writes below the mixer threshold,
 *     so the press tone sat queued until the release tone arrived and both
 *     played together, at the end
 *
 * SoundPool is built for exactly this job: short effects, decoded once, held in
 * memory, played with minimal latency and no buffer bookkeeping of our own. The
 * samples are still synthesised rather than shipped as assets, because an
 * apktool project has no resource pipeline - they are written to the app's cache
 * as small WAVs for SoundPool to load.
 *
 * Why a chirp: these radios are used on sites and at height, where wind and
 * machinery mask a steady tone. A frequency that moves is easier to pick out of
 * broadband noise, and the direction of the sweep says which edge it was without
 * the operator having to think about pitch.
 */
public final class Tone {

    private static final int RATE = 22050;
    private static final int SEG_MS = 70;       // per half of the chirp
    private static final int RAMP_MS = 4;       // anti-click attack/decay

    private static boolean sInited = false;
    private static boolean sEnabled = false;
    private static float sVolume = 1.0f;

    private static SoundPool sPool;
    private static int sPressId = -1;
    private static int sReleaseId = -1;
    private static int sErrorId = -1;

    private Tone() { }

    public static void press(Context ctx) {
        play(ctx, 1);
    }

    public static void release(Context ctx) {
        play(ctx, 2);
    }

    /** Not connected. Deliberately not silence - a dead button reads as a dead radio. */
    public static void error(Context ctx) {
        play(ctx, 3);
    }

    private static synchronized void play(Context ctx, int which) {
        ensureInit(ctx);
        if (!sEnabled || sPool == null) {
            return;
        }
        int id = (which == 1) ? sPressId : (which == 2) ? sReleaseId : sErrorId;
        if (id > 0) {
            sPool.play(id, sVolume, sVolume, 1, 0, 1.0f);
        }
    }

    private static void ensureInit(Context ctx) {
        if (sInited) {
            return;
        }
        sInited = true;

        int vol = 100;
        BufferedReader r = null;
        try {
            r = new BufferedReader(new FileReader("/data/local/tmp/knob.conf"));
            String line;
            while ((line = r.readLine()) != null) {
                int eq = line.indexOf('=');
                if (eq <= 0) {
                    continue;
                }
                String k = line.substring(0, eq).trim();
                String v = line.substring(eq + 1).trim();
                if ("ptt_tone".equals(k)) {
                    sEnabled = "true".equalsIgnoreCase(v) || "1".equals(v) || "yes".equalsIgnoreCase(v);
                } else if ("ptt_tone_volume".equals(k)) {
                    try {
                        vol = Integer.parseInt(v);
                    } catch (NumberFormatException ignored) {
                    }
                }
            }
        } catch (Exception e) {
            // No config, no tone. Off is the safe default for existing radios.
        } finally {
            if (r != null) {
                try { r.close(); } catch (Exception ignored) { }
            }
        }
        sVolume = Math.max(0, Math.min(100, vol)) / 100f;
        android.util.Log.i("pttbridge", "Tone config enabled=" + sEnabled + " vol=" + vol);

        if (!sEnabled || ctx == null) {
            return;
        }
        try {
            File dir = ctx.getCacheDir();
            File p = wav(new File(dir, "porto_press.wav"), 800, 1200);
            File q = wav(new File(dir, "porto_release.wav"), 1200, 800);
            File e = wav(new File(dir, "porto_error.wav"), 300, 300);

            sPool = new SoundPool(4, AudioManager.STREAM_MUSIC, 0);
            sPressId = sPool.load(p.getAbsolutePath(), 1);
            sReleaseId = sPool.load(q.getAbsolutePath(), 1);
            sErrorId = sPool.load(e.getAbsolutePath(), 1);
            android.util.Log.i("pttbridge", "Tone loaded ids "
                    + sPressId + "/" + sReleaseId + "/" + sErrorId);
        } catch (Throwable t) {
            android.util.Log.w("pttbridge", "tone init failed: " + t);
            sPool = null;
        }
    }

    /** Write a mono 16-bit PCM WAV of two steady segments, f1 then f2. */
    private static File wav(File out, int f1, int f2) throws Exception {
        int per = RATE * SEG_MS / 1000;
        int frames = per * 2;
        int dataLen = frames * 2;
        byte[] b = new byte[44 + dataLen];
        hdr(b, dataLen);

        int ramp = Math.max(1, RATE * RAMP_MS / 1000);
        double phase = 0.0;
        for (int i = 0; i < frames; i++) {
            int f = (i < per) ? f1 : f2;
            phase += 2.0 * Math.PI * f / RATE;
            double env = 1.0;
            if (i < ramp) {
                env = i / (double) ramp;
            } else if (i > frames - ramp) {
                env = (frames - i) / (double) ramp;
            }
            short s = (short) (Math.sin(phase) * env * 0.8 * Short.MAX_VALUE);
            b[44 + i * 2] = (byte) (s & 0xff);
            b[44 + i * 2 + 1] = (byte) ((s >> 8) & 0xff);
        }

        FileOutputStream fos = new FileOutputStream(out);
        try {
            fos.write(b);
        } finally {
            fos.close();
        }
        return out;
    }

    private static void hdr(byte[] b, int dataLen) {
        put(b, 0, "RIFF");
        le32(b, 4, 36 + dataLen);
        put(b, 8, "WAVE");
        put(b, 12, "fmt ");
        le32(b, 16, 16);            // PCM chunk size
        le16(b, 20, 1);             // format = PCM
        le16(b, 22, 1);             // mono
        le32(b, 24, RATE);
        le32(b, 28, RATE * 2);      // byte rate
        le16(b, 32, 2);             // block align
        le16(b, 34, 16);            // bits per sample
        put(b, 36, "data");
        le32(b, 40, dataLen);
    }

    private static void put(byte[] b, int off, String s) {
        for (int i = 0; i < s.length(); i++) {
            b[off + i] = (byte) s.charAt(i);
        }
    }

    private static void le16(byte[] b, int off, int v) {
        b[off] = (byte) (v & 0xff);
        b[off + 1] = (byte) ((v >> 8) & 0xff);
    }

    private static void le32(byte[] b, int off, int v) {
        b[off] = (byte) (v & 0xff);
        b[off + 1] = (byte) ((v >> 8) & 0xff);
        b[off + 2] = (byte) ((v >> 16) & 0xff);
        b[off + 3] = (byte) ((v >> 24) & 0xff);
    }
}
