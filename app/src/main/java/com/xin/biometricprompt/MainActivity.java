package com.xin.biometricprompt;

import android.hardware.biometrics.BiometricPrompt;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Build;
import android.os.Bundle;
import android.security.keystore.KeyProperties;
import android.text.TextUtils;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.widget.Toast;

import androidx.annotation.RequiresApi;
import androidx.appcompat.app.AppCompatActivity;

import com.xin.biometricprompt.bio.BioAuthCallback;
import com.xin.biometricprompt.bio.Biometric;
import com.xin.biometricprompt.fp.FpManagerAuthCallback;
import com.xin.biometricprompt.fp.FpOperation;
import com.xin.biometricprompt.keystore.ExtensionParser;
import com.xin.biometricprompt.keystore.KeyAttestationExample;
import com.xin.biometricprompt.keystore.KeyStoreHelper;
import com.xin.biometricprompt.keystore.attestation.KeyASecurityType;
import com.xin.biometricprompt.keystore.sample.Constants;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.UUID;

import javax.crypto.Cipher;

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


    public static final String KEY_ALIAS = UUID.randomUUID().toString();


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
        findViewById(R.id.btn_compare_cert_public_key).setOnClickListener(this);

        findViewById(R.id.btn_encrypt).setOnClickListener(this);
        findViewById(R.id.btn_decrypt).setOnClickListener(this);

        findViewById(R.id.btn_java_rsa_encrypt).setOnClickListener(this);
    }

    @RequiresApi(api = Build.VERSION_CODES.N)
    @Override
    public void onClick(View view) {
        switch (view.getId()) {
            case R.id.btn_register:
                try {
                    KeyStoreHelper keyStoreHelper = KeyStoreHelper.getInstance();
                    keyStoreHelper.generateKeyPair();

                    final Signature signature = keyStoreHelper.initSign();

                    if (signature == null)
                        return;

                    if (Build.VERSION.SDK_INT >= 28) {
                        if (!Biometric.isSupportBiometric(MainActivity.this))
                            return;

                        BiometricPrompt biometricPrompt = Biometric.createPrompt(MainActivity.this,
                                "指纹验证",
                                "Android Keystore Generate Key Pair",
                                "对数据进行签名"
                        );

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

                        final FpAuthUI authUI = new FpAuthUI();

                        FpOperation fpOperation = FpOperation.getInstance(MainActivity.this);

                        FpManagerAuthCallback authCallback = new FpManagerAuthCallback(authUI, FpManagerAuthCallback.OPERATION_TYPE.SIGN);

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
                try {
                    // old version current use
                    KeyASecurityType keyASecurityType = ExtensionParser.getASecurityLevel(KEY_ALIAS);
                    Log.wtf(TAG, "GMRZ project use:" + keyASecurityType.toString());

                    // new version google sample code
                    Certificate[] certChain = ExtensionParser.getCertChain(KEY_ALIAS);
                    X509Certificate[] certs = new X509Certificate[certChain.length];

                    int i = 0;
                    for (Certificate certificate : certChain) {
                        byte[] encodedCert = certificate.getEncoded();
                        ByteArrayInputStream inputStream = new ByteArrayInputStream(encodedCert);

                        CertificateFactory factory = CertificateFactory.getInstance("X.509");
                        certs[i] = (X509Certificate) factory.generateCertificate(inputStream);

                        i++;
                    }

                    //
                    //
                    X509Certificate x509Certificate = certs[certChain.length - 1];
                    //byte[] encoded = x509Certificate.getTBSCertificate();
                    byte[] encoded = x509Certificate.getEncoded(); // 和TBS不一样
                    Log.wtf(TAG, "last one cert: " + android.util.Base64.encodeToString(encoded, android.util.Base64.DEFAULT));


                    //


                    KeyAttestationExample.main(certs);

                } catch (Exception e) {
                    e.printStackTrace();
                }
                break;

            case R.id.btn_encrypt:

                try {
                    KeyStoreHelper keyStoreHelper = KeyStoreHelper.getInstance();
                    keyStoreHelper.generateAESKey();

                    Cipher cipher = keyStoreHelper.getCipher(KeyProperties.PURPOSE_ENCRYPT, null);

                    //
                    FpAuthUI authUI = new FpAuthUI();

                    FpOperation fpOperation = FpOperation.getInstance(MainActivity.this);
                    FpManagerAuthCallback authCallback = new FpManagerAuthCallback(authUI, FpManagerAuthCallback.OPERATION_TYPE.ENCRYPT);

                    authCallback.setSrcData(SRC_DATA);

                    authCallback.setCallback(new FpManagerAuthCallback.Callback() {
                        @Override
                        public void onProcessed(String text) {

                        }
                    });

                    fpOperation.startListening(new FingerprintManager.CryptoObject(cipher), authCallback);
                    authUI.show(getSupportFragmentManager(), "my_dialog");

                } catch (Exception e) {
                    e.printStackTrace();
                }


                break;

            case R.id.btn_decrypt:

                try {
                    KeyStoreHelper keyStoreHelper = KeyStoreHelper.getInstance();
                    Cipher cipher = keyStoreHelper.getCipher(KeyProperties.PURPOSE_DECRYPT, FpManagerAuthCallback.iv);

                    //
                    FpAuthUI authUI = new FpAuthUI();

                    FpOperation fpOperation = FpOperation.getInstance(MainActivity.this);
                    FpManagerAuthCallback authCallback = new FpManagerAuthCallback(authUI, FpManagerAuthCallback.OPERATION_TYPE.DECRYPT);

                    //authCallback.setSrcData(SRC_DATA);

                    authCallback.setCallback(new FpManagerAuthCallback.Callback() {
                        @Override
                        public void onProcessed(String text) {

                        }
                    });

                    fpOperation.startListening(new FingerprintManager.CryptoObject(cipher), authCallback);
                    authUI.show(getSupportFragmentManager(), "my_dialog");

                } catch (Exception e) {
                    e.printStackTrace();
                }
                break;

            case R.id.btn_java_rsa_encrypt:
                KeyStoreHelper ksHelper = KeyStoreHelper.getInstance();
                try {
                    ksHelper.haha(this);
                } catch (Exception e) {
                    e.printStackTrace();
                }
                break;

            case R.id.btn_compare_cert_public_key:
                // 官方硬实现 官方新旧根证书公钥对比测试
                try {
                    CertificateFactory certificateFactory = CertificateFactory.getInstance("x509");

                    // Google Android keystore key attestation root cert
                    Certificate googleRootCertificate = certificateFactory
                            .generateCertificate(new ByteArrayInputStream(Constants.GOOGLE_ROOT_CERTIFICATE.getBytes()));
                    byte[] pubkey1 = googleRootCertificate.getPublicKey().getEncoded();

                    // Google Android keystore key attestation root cert. new version
                    // 新版5G手机会预置新版的根证书. 新版证书的签发时间更新. 证书公钥与原有一致.
                    InputStream inputStream = getResources().openRawResource(R.raw.certificate);
                    Certificate newGoogleRootVivo5gCert = certificateFactory.generateCertificate(inputStream);
                    byte[] pubkey2 = newGoogleRootVivo5gCert.getPublicKey().getEncoded();

                    boolean equals = Arrays.equals(pubkey1, pubkey2);
                    Toast.makeText(this, equals ? "公钥相等" : "公钥不相等", Toast.LENGTH_SHORT).show();

                    // 2020/6/3 Google 官网新增一张 KeyStore Key Attestation 根证书 (硬实现)
                    InputStream ins = getResources().openRawResource(R.raw.certificate_google_new);
                    Certificate googleNewOfficialCert = certificateFactory.generateCertificate(ins);
                    byte[] vivoCert = newGoogleRootVivo5gCert.getEncoded();
                    byte[] newOfficialCert = googleNewOfficialCert.getEncoded();

                    Log.wtf(TAG, "vivo 5g cert is equals with new official root cert:"
                            + Arrays.equals(vivoCert, newOfficialCert));

                } catch (Exception e) {
                    e.printStackTrace();
                }
                break;
        }
    }
}
