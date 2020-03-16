package com.xin.biometricprompt.fp;

import android.content.Context;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Build;
import android.os.CancellationSignal;

import androidx.annotation.RequiresApi;

@RequiresApi(api = Build.VERSION_CODES.M)
public class FpOperation {

    private FingerprintManager manager;
    private CancellationSignal cancelSignal;

    private static FpOperation instance;

    public static FpOperation getInstance(Context context) {
        if (instance == null) {
            instance = new FpOperation(context);
        }
        return instance;
    }

    private FpOperation(Context context) {
        manager = (FingerprintManager) context.getSystemService(Context.FINGERPRINT_SERVICE);

        cancelSignal = new CancellationSignal();
        cancelSignal.setOnCancelListener(new CancellationSignal.OnCancelListener() {
            @Override
            public void onCancel() {

            }
        });
    }

    public void startListening(FingerprintManager.CryptoObject cryptoObj, FingerprintManager.AuthenticationCallback callback) {

        manager.authenticate(cryptoObj, cancelSignal, 0, callback, null);
    }

    public void stopListening() {
        cancelSignal.cancel();
    }

    public boolean isEnrolledFingerprints() {
        return manager.hasEnrolledFingerprints();
    }
}
