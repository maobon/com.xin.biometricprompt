package com.xin.biometricprompt.fp;

import android.hardware.fingerprint.FingerprintManager;
import android.os.Build;
import android.text.TextUtils;
import android.util.Base64;
import android.util.Log;

import androidx.annotation.RequiresApi;
import androidx.fragment.app.DialogFragment;

import com.xin.biometricprompt.FpAuthUI;

import java.security.Signature;

import javax.crypto.Cipher;


@RequiresApi(api = Build.VERSION_CODES.M)
public class FpManagerAuthCallback extends FingerprintManager.AuthenticationCallback {

    private static final String TAG = "FpAuthCallback";

    public static byte[] encryptedData;
    public static byte[] iv;

    private String srcData;
    private Callback callback;

    private DialogFragment dialogFragment;

    private OPERATION_TYPE opType;

    public enum OPERATION_TYPE {

        SIGN, // 签名验签

        ENCRYPT, // 加密

        DECRYPT // 解密
    }

    @SuppressWarnings("deprecation")
    public FpManagerAuthCallback(DialogFragment dialogFragment, OPERATION_TYPE opType) {
        this.dialogFragment = dialogFragment;
        this.opType = opType;
    }

    @Override
    public void onAuthenticationError(int errorCode, CharSequence errString) {
        super.onAuthenticationError(errorCode, errString);

        Log.d(TAG, "onAuthenticationError: " + errorCode);

        // 3 FINGERPRINT_ERROR_TIMEOUT
        // 7 FINGERPRINT_ERROR_LOCKOUT // 30 seconds
        // 5 ....
        // 9 FINGERPRINT_ERROR_LOCKOUT_PERMANENT

        if (errorCode != 5) {
            //dialogFragment.dismissAllowingStateLoss();
            ((FpAuthUI) dialogFragment).setMsg("error_code: " + errString);

        }

        // TODO - 需要根据ERROR_CODE 细化 处理控制UI


    }

    @Override
    public void onAuthenticationFailed() {
        super.onAuthenticationFailed();

        Log.d(TAG, "onAuthenticationFailed");

    }

    @Override
    public void onAuthenticationHelp(int helpCode, CharSequence helpString) {
        super.onAuthenticationHelp(helpCode, helpString);


        Log.d(TAG, "onAuthenticationHelp");


    }

    @Override
    public void onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result) {
        super.onAuthenticationSucceeded(result);

        Log.d(TAG, "onAuthenticationSucceeded");

        dialogFragment.dismissAllowingStateLoss();

        String signed = null;
        try {

            switch (opType) {
                case SIGN:
                    if (TextUtils.isEmpty(srcData))
                        throw new IllegalArgumentException("src data is null");

                    // signature
                    Signature signature = result.getCryptoObject().getSignature();
                    signature.update(srcData.getBytes());

                    byte[] sign = signature.sign();
                    signed = Base64.encodeToString(sign, Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING);
                    break;


                case ENCRYPT:
                    if (TextUtils.isEmpty(srcData))
                        throw new IllegalArgumentException("src data is null");

                    // cipher
                    Cipher cipher = result.getCryptoObject().getCipher();



                    encryptedData = cipher.doFinal(srcData.getBytes());
                    encryptedData = Base64.encode(encryptedData, Base64.DEFAULT);

                    iv = cipher.getIV();

                    Log.wtf(TAG, "ok...");

                    break;


                case DECRYPT:
                    // cipher
                    Cipher c = result.getCryptoObject().getCipher();
                    byte[] bytes = c.doFinal(Base64.decode(encryptedData, Base64.DEFAULT));

                    Log.wtf(TAG, "ok..." + new String(bytes));

                    break;
            }


        } catch (Exception e) {
            e.printStackTrace();
        }

        if (callback != null)
            callback.onProcessed(signed);
    }

    public interface Callback {

        void onProcessed(String text);
    }

    public void setSrcData(String srcData) {
        this.srcData = srcData;
    }

    public void setCallback(Callback callback) {
        this.callback = callback;
    }
}
