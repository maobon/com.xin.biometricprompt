package com.xin.biometricprompt.bio;

import android.hardware.biometrics.BiometricPrompt;
import androidx.annotation.RequiresApi;
import android.text.TextUtils;
import android.util.Base64;

import java.security.Signature;

@RequiresApi(api = 28)
public class BioAuthCallback extends BiometricPrompt.AuthenticationCallback {

    private String srcData;
    private Callback callback;

    @Override
    public void onAuthenticationError(int errorCode, CharSequence errString) {
        super.onAuthenticationError(errorCode, errString);
    }

    @Override
    public void onAuthenticationHelp(int helpCode, CharSequence helpString) {
        super.onAuthenticationHelp(helpCode, helpString);
    }

    @Override
    public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result) {
        super.onAuthenticationSucceeded(result);

        String signed = null;
        try {
            Signature signature = result.getCryptoObject().getSignature();
            if (TextUtils.isEmpty(srcData))
                throw new IllegalArgumentException("src data is null");
            signature.update(srcData.getBytes());
            byte[] sign = signature.sign();
            signed = Base64.encodeToString(sign, Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING);
        } catch (Exception e) {
            e.printStackTrace();
        }

        if (callback != null)
            callback.onProcessed(signed);
    }

    @Override
    public void onAuthenticationFailed() {
        super.onAuthenticationFailed();
    }

    public interface Callback {
        void onProcessed(String text);
    }

    public void setCallback(Callback callback) {
        this.callback = callback;
    }

    public void setSrcData(String srcData) {
        this.srcData = srcData;
    }
}
