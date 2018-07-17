package com.xin.biometricprompt;

import android.util.Log;

public class Logger {

    private Logger() {
    }

    public static boolean isDebug = true;

    public static void i(String tag, String msg) {
        if (isDebug)
            Log.i(tag, msg);
    }

    public static void d(String tag, String msg) {
        if (isDebug)
            Log.d(tag, msg);
    }

    public static void e(String tag, String msg) {
        if (isDebug)
            Log.e(tag, msg);
    }

    public static void v(String tag, String msg) {
        if (isDebug)
            Log.v(tag, msg);
    }

    public static void wtf(String tag, String msg) {
        if (isDebug)
            Log.wtf(tag, msg);
    }
}