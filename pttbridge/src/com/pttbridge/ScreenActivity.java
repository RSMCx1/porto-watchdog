package com.pttbridge;

import android.app.Activity;
import android.graphics.Color;
import android.graphics.Typeface;
import android.os.Bundle;
import android.os.Handler;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.view.Window;
import android.view.WindowManager;
import android.widget.LinearLayout;
import android.widget.TextView;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;

/**
 * The radio's idle screen: current channel, large, and the radio's own name.
 *
 * The TE300K gets this from a patched vendor idle-screen app, which does not
 * exist on other radios - so this is the portable replacement. Deliberately
 * bare: no settings, no action bar, no status bar. An operator glancing at a
 * radio on their chest wants one thing, which is what channel they are on.
 *
 * Data comes from SCREENVARS_FILE (/data/local/tmp/screenvars.txt), which the
 * daemon rewrites every time the server sends a 'C' channel packet:
 *
 *     channel=TAC 1
 *     id=P4
 *
 * Polled rather than watched with FileObserver: the daemon writes by truncating
 * and rewriting, which can present as several inotify events for one logical
 * update, and a one-second poll on two short lines costs nothing measurable.
 *
 * The UI is built in code on purpose. This is an apktool/smali project, so
 * introducing an XML layout would drag in resource recompilation and a new
 * R class; a programmatic view tree keeps the build to javac -> d8 -> smali.
 */
public class ScreenActivity extends Activity {

    private static final String SCREENVARS = "/data/local/tmp/screenvars.txt";
    private static final long POLL_MS = 1000;

    /** Panel padding in pixels. fitSize() measures against what is left of the width. */
    private static final int PAD = 8;

    private TextView mChannel;
    private TextView mId;
    private Handler mHandler;
    private String mLastChannel = null;
    private String mLastId = null;

    private final Runnable mPoll = new Runnable() {
        @Override
        public void run() {
            refresh();
            mHandler.postDelayed(this, POLL_MS);
        }
    };

    @Override
    protected void onCreate(Bundle saved) {
        super.onCreate(saved);
        requestWindowFeature(Window.FEATURE_NO_TITLE);
        getWindow().setFlags(WindowManager.LayoutParams.FLAG_FULLSCREEN,
                             WindowManager.LayoutParams.FLAG_FULLSCREEN);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setGravity(Gravity.CENTER);
        root.setBackgroundColor(Color.BLACK);
        root.setPadding(PAD, PAD, PAD, PAD);

        // Channel is the thing you read at a glance, so it gets the room.
        mChannel = new TextView(this);
        mChannel.setTextColor(Color.WHITE);
        mChannel.setTypeface(Typeface.DEFAULT_BOLD);
        mChannel.setGravity(Gravity.CENTER);
        mChannel.setSingleLine(false);
        mChannel.setTextSize(TypedValue.COMPLEX_UNIT_SP, 34);

        // The radio's own name matters far less - it never changes in use.
        mId = new TextView(this);
        mId.setTextColor(Color.parseColor("#8899AA"));
        mId.setGravity(Gravity.CENTER);
        mId.setSingleLine(true);
        mId.setTextSize(TypedValue.COMPLEX_UNIT_SP, 14);

        root.addView(mChannel, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT));
        root.addView(mId, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT));

        setContentView(root);
        mHandler = new Handler();
        refresh();
    }

    @Override
    protected void onResume() {
        super.onResume();
        // Hide the navigation/status furniture again; some launchers restore it.
        getWindow().getDecorView().setSystemUiVisibility(
                View.SYSTEM_UI_FLAG_LOW_PROFILE | View.SYSTEM_UI_FLAG_FULLSCREEN);
        mHandler.removeCallbacks(mPoll);
        mHandler.post(mPoll);
    }

    @Override
    protected void onPause() {
        super.onPause();
        mHandler.removeCallbacks(mPoll);   // never poll while off screen
    }

    /**
     * Largest size at which this text fits one line across the panel.
     *
     * Measured rather than tabulated: a step-down table keyed on character count
     * guesses wrong the moment a name is wide ("Disconnected" wrapped to
     * "Disconnecte" + "d"), because glyph widths differ. Paint.measureText scales
     * linearly with text size, so one measurement gives the exact ratio and the
     * answer needs no loop.
     */
    private int fitSize(String text) {
        final int max = 46;
        final int min = 12;
        int avail = getResources().getDisplayMetrics().widthPixels - (PAD * 2) - 2;
        if (avail <= 0 || text.length() == 0) {
            return max;
        }
        android.graphics.Paint p = new android.graphics.Paint(mChannel.getPaint());
        p.setTextSize(max);
        float w = p.measureText(text);
        if (w <= avail) {
            return max;
        }
        int fitted = (int) Math.floor(max * avail / w);
        return Math.max(min, Math.min(max, fitted));
    }

    /** Re-read the file and update only when something actually changed. */
    private void refresh() {
        String channel = null;
        String id = null;
        File f = new File(SCREENVARS);
        BufferedReader r = null;
        try {
            r = new BufferedReader(new FileReader(f));
            String line;
            while ((line = r.readLine()) != null) {
                int eq = line.indexOf('=');
                if (eq <= 0) {
                    continue;
                }
                String k = line.substring(0, eq).trim();
                String v = line.substring(eq + 1).trim();
                if ("channel".equals(k)) {
                    channel = v;
                } else if ("id".equals(k)) {
                    id = v;
                }
            }
        } catch (Exception e) {
            // Missing or unreadable is normal before the first 'C' packet
            // arrives; show a holding message rather than an error.
        } finally {
            if (r != null) {
                try {
                    r.close();
                } catch (Exception ignored) {
                }
            }
        }

        // No channel means no server. An empty screen would read as "working,
        // quiet" when the truth is the opposite, so say it outright.
        //
        // Known gap: the daemon writes this file on a 'C' packet but does not
        // blank it when the link drops, so a radio that loses coverage keeps
        // showing its last channel. The fix belongs in knob_reader.c.
        if (channel == null || channel.length() == 0) {
            channel = "Disconnected";
        }
        if (id == null) {
            id = "";
        }

        if (!channel.equals(mLastChannel)) {
            mChannel.setText(channel);
            mChannel.setTextSize(TypedValue.COMPLEX_UNIT_PX, fitSize(channel));
            mLastChannel = channel;
        }
        if (!id.equals(mLastId)) {
            mId.setText(id);
            mLastId = id;
        }
    }
}
