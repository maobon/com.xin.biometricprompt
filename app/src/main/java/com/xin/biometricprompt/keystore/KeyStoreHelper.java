package com.xin.biometricprompt.keystore;

import android.content.Context;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import org.json.JSONArray;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.UUID;

public class KeyStoreHelper {

    private static final String KEY_ALIAS = UUID.randomUUID().toString();

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
        //Calendar notBefore = Calendar.getInstance();
        //Calendar notAfter = Calendar.getInstance();
        //notAfter.add(Calendar.YEAR, 1);

        //X500Principal certificateSubject = new X500Principal(String.format("CN=%s,OU=%s", KEY_ALIAS, context.getPackageName()));

        KeyPairGenerator kpGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");

        KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(KEY_ALIAS, KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(new ECGenParameterSpec("prime256v1"))
                .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA384, KeyProperties.DIGEST_SHA512)
                //.setCertificateSubject(certificateSubject)
                //.setCertificateNotBefore(notBefore.getTime())
                //.setCertificateNotAfter(notAfter.getTime())
                .setUserAuthenticationRequired(true)
                .setAttestationChallenge(genChallenge()); // 24 Android N 以后才开始有的

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

    public String exportKeyAttestation(String alias) throws Exception {
        StringBuilder sb = new StringBuilder();
        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);

        Certificate[] certArr = ks.getCertificateChain(alias);

        String[] certArray = new String[certArr.length];

        int i = 0;
        for (Certificate cert : certArr) {
            byte[] buf = cert.getEncoded();
            certArray[i] = new String(Base64.encode(buf, Base64.DEFAULT));
            i++;
        }

        JSONArray jsonArray = new JSONArray(certArray);
        String key_attestation_data = jsonArray.toString();
        sb.append(key_attestation_data);
        return sb.toString();
    }


    /**
     * 挑战值
     */
    private byte[] genChallenge() {
        SecureRandom random = new SecureRandom();
        byte[] challenge = new byte[32];
        random.nextBytes(challenge);
        return challenge;
    }

}
