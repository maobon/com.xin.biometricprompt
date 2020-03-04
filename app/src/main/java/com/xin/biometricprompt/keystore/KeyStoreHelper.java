package com.xin.biometricprompt.keystore;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import java.nio.charset.Charset;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;

import static com.xin.biometricprompt.MainActivity.KEY_ALIAS;

public class KeyStoreHelper {

    private static final String TAG = "KS";

    private static KeyStoreHelper instance;

    public static KeyStoreHelper getInstance() {
        if (instance == null) {
            instance = new KeyStoreHelper();
        }
        return instance;
    }

    private KeyStoreHelper() {
    }

    public KeyPair generateKeyPair() throws Exception {

        // ALG_ECC
        KeyPairGenerator kpGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");

        KeyGenParameterSpec.Builder builder =
                new KeyGenParameterSpec.Builder(KEY_ALIAS, KeyProperties.PURPOSE_SIGN)
                        .setDigests(KeyProperties.DIGEST_SHA256)
                        .setUserAuthenticationRequired(true)
                        .setAttestationChallenge("THIS_IS_ATTESTATION_CHALLENGE_VALUE".getBytes()); // 24 Android N 以后才开始有的

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
