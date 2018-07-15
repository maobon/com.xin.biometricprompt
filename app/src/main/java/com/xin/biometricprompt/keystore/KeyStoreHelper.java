package com.xin.biometricprompt.keystore;

import android.content.Context;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Calendar;

import javax.security.auth.x500.X500Principal;

public class KeyStoreHelper {

    private static final String KEY_ALIAS = "test";

    private static KeyStoreHelper instance;

    public static KeyStoreHelper getInstance() {
        if (instance == null) {
            instance = new KeyStoreHelper();
        }
        return instance;
    }

    private KeyStoreHelper() {
    }

    public KeyPair generateKeyPair(Context context) throws Exception {
        Calendar notBefore = Calendar.getInstance();
        Calendar notAfter = Calendar.getInstance();
        notAfter.add(Calendar.YEAR, 1);

        X500Principal certificateSubject = new X500Principal(String.format("CN=%s,OU=%s", KEY_ALIAS, context.getPackageName()));

        KeyPairGenerator kpGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");

        KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(KEY_ALIAS, KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(new ECGenParameterSpec("prime256v1"))
                .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA384, KeyProperties.DIGEST_SHA512)
                .setCertificateSubject(certificateSubject)
                .setCertificateNotBefore(notBefore.getTime())
                .setCertificateNotAfter(notAfter.getTime())
                .setUserAuthenticationRequired(true);

        kpGenerator.initialize(builder.build());
        return kpGenerator.generateKeyPair();
    }

    public Signature initSign() throws Exception {
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(getKeyPair().getPrivate());
        return signature;
    }

    public Signature initVerify() throws Exception {
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initVerify(getKeyPair().getPublic());
        return signature;
    }

    private KeyPair getKeyPair() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);

        Certificate certificate = keyStore.getCertificate(KEY_ALIAS);
        PublicKey publicKey = certificate.getPublicKey();
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(KEY_ALIAS, null);

        return new KeyPair(publicKey, privateKey);
    }
}
