package com.xin.biometricprompt;

import android.hardware.biometrics.BiometricPrompt;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Build;
import android.os.Bundle;
import android.text.TextUtils;
import android.util.Base64;
import android.view.View;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import com.xin.biometricprompt.bio.BioAuthCallback;
import com.xin.biometricprompt.bio.Biometric;
import com.xin.biometricprompt.fp.FpManagerAuthCallback;
import com.xin.biometricprompt.fp.FpOperation;
import com.xin.biometricprompt.keystore.KeyStoreHelper;

import java.security.Signature;

/**
 * Android P 生物识别提示框
 * <p>
 * P use BiometricPrompt
 * M and N or other old version use FingerprintManager
 * <p>
 * ALG: Fido Keystore - ECDSA sign data
 */

public class MainActivity extends AppCompatActivity implements View.OnClickListener {

    private static final String TAG = "MainActivity";

    private static final String SRC_DATA = "Hello!Android P version, biometric prompt demo.";
    private String dataSigned;


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        initViews();
    }

    private void initViews() {
        findViewById(R.id.btn_register).setOnClickListener(this);
        findViewById(R.id.btn_auth).setOnClickListener(this);
        findViewById(R.id.btn_export_key_attestation).setOnClickListener(this);
    }

    @Override
    public void onClick(View view) {
        switch (view.getId()) {
            case R.id.btn_register:
                try {
                    KeyStoreHelper keyStoreHelper = KeyStoreHelper.getInstance();
                    keyStoreHelper.generateKeyPair(MainActivity.this);
                    final Signature signature = keyStoreHelper.initSign();

                    if (signature == null)
                        return;

                    if (Build.VERSION.SDK_INT >= 28) {
                        if (!Biometric.isSupportBiometric(MainActivity.this))
                            return;

                        BiometricPrompt biometricPrompt = Biometric.createPrompt(MainActivity.this, "指纹验证", "Android Keystore Generate Key Pair", "对数据进行签名");
                        BioAuthCallback authCallback = new BioAuthCallback();
                        authCallback.setSrcData(SRC_DATA);
                        authCallback.setCallback(new BioAuthCallback.Callback() {
                            @Override
                            public void onProcessed(String text) {
                                dataSigned = text;

                                runOnUiThread(new Runnable() {
                                    @Override
                                    public void run() {
                                        Toast.makeText(MainActivity.this, "签名完成", Toast.LENGTH_SHORT).show();
                                    }
                                });
                            }
                        });

                        biometricPrompt.authenticate(
                                new BiometricPrompt.CryptoObject(signature),
                                Biometric.createCancelSignal(),
                                getMainExecutor(),
                                authCallback
                        );

                    } else {

                        final AuthUI authUI = new AuthUI();

                        FpOperation fpOperation = FpOperation.getInstance(MainActivity.this);

                        FpManagerAuthCallback authCallback = new FpManagerAuthCallback(authUI);

                        authCallback.setSrcData(SRC_DATA);
                        authCallback.setCallback(new FpManagerAuthCallback.Callback() {
                            @Override
                            public void onProcessed(String text) {
                                dataSigned = text;

                                runOnUiThread(new Runnable() {
                                    @Override
                                    public void run() {
                                        Toast.makeText(MainActivity.this, "签名完成", Toast.LENGTH_SHORT).show();
                                    }
                                });
                            }
                        });

                        fpOperation.startListening(new FingerprintManager.CryptoObject(signature), authCallback);

                        authUI.show(getSupportFragmentManager(), "my_dialog");

                        //...
                        /*FragmentTransaction ft = getSupportFragmentManager().beginTransaction();
                        Fragment prev = getSupportFragmentManager().findFragmentByTag("my_dialog");
                        if (prev != null) {
                            Log.wtf(TAG, "之前的不为空 移除");
                            ft.remove(prev);
                        }

                        ft.addToBackStack(null);*/


                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
                break;

            case R.id.btn_auth:
                if (TextUtils.isEmpty(dataSigned))
                    return;

                try {
                    byte[] decode = Base64.decode(dataSigned, Base64.NO_WRAP | Base64.NO_PADDING | Base64.URL_SAFE);
                    Signature signature = KeyStoreHelper.getInstance().initVerify();
                    signature.update(SRC_DATA.getBytes());
                    boolean verify = signature.verify(decode);
                    Toast.makeText(MainActivity.this, verify ? "验签通过" : "验签失败", Toast.LENGTH_SHORT).show();
                } catch (Exception e) {
                    e.printStackTrace();
                }
                break;

            case R.id.btn_export_key_attestation:

//                 KeyASecurityType test = FpUtil.getASecurityLevel("test");
//                 Log.wtf(TAG, test.toString());

                try {
                    KeyStoreHelper.getInstance().exportKeyAttestation("test");
                } catch (Exception e) {
                    e.printStackTrace();
                }
                break;
        }
    }
}
