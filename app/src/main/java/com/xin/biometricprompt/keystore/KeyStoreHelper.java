package com.xin.biometricprompt.keystore;

import android.content.Context;
import android.os.Build;
import android.security.KeyPairGeneratorSpec;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;
import android.util.Log;

import androidx.annotation.RequiresApi;

import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.util.Calendar;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import javax.security.auth.x500.X500Principal;

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

    @RequiresApi(api = Build.VERSION_CODES.N)
    public KeyPair generateKeyPair() throws Exception {

        // ALG_ECC
        KeyPairGenerator kpGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");

        // ALG RSA
        // KeyPairGenerator kpGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore");

        KeyGenParameterSpec.Builder builder =
                new KeyGenParameterSpec.Builder(KEY_ALIAS, KeyProperties.PURPOSE_SIGN)
                        .setDigests(KeyProperties.DIGEST_SHA256)
                        // .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1) //... RSA

                        .setUserAuthenticationRequired(true)
                        .setAttestationChallenge("THIS_IS_ATTESTATION_CHALLENGE_VALUE".getBytes()); // 24 Android N 以后才开始有的

        kpGenerator.initialize(builder.build());
        return kpGenerator.generateKeyPair();
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    public Signature initSign() throws Exception {
        // ECC
        Signature signature = Signature.getInstance("SHA256withECDSA");

        // RSA
        // Signature signature = Signature.getInstance("SHA256withRSA");

        signature.initSign(getKeyPair().getPrivate());
        return signature;
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    public Signature initVerify() throws Exception {
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initVerify(getKeyPair().getPublic());
        return signature;
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    private KeyPair getKeyPair() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);

        Certificate certificate = keyStore.getCertificate(KEY_ALIAS);
        PublicKey publicKey = certificate.getPublicKey();
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(KEY_ALIAS, null);

        Log.wtf(TAG, "私钥保存在安全硬件中??:" + isPriInsideSecureHardware(privateKey));

        return new KeyPair(publicKey, privateKey);
    }

    // 查看私钥位置 一般都在TEE中 几乎没有私钥在外面的设备
    @RequiresApi(api = Build.VERSION_CODES.M)
    private boolean isPriInsideSecureHardware(PrivateKey privateKey) throws Exception {

        KeyFactory factory = KeyFactory.getInstance(privateKey.getAlgorithm(), "AndroidKeyStore");
        KeyInfo keySpec = factory.getKeySpec(privateKey, KeyInfo.class);

        // if the key resides inside secure hardware (e.g., Trusted Execution Environment (TEE) or Secure Element (SE)).
        // Key material of such keys is available in plaintext only inside the secure hardware and is not exposed outside of it.
        boolean insideSecureHardware = keySpec.isInsideSecureHardware();

        // Whether a key's user authentication authorization is enforced by the secure hardware can be queried using
        boolean userAuthenticationRequirementEnforcedBySecureHardware =
                keySpec.isUserAuthenticationRequirementEnforcedBySecureHardware(); // 等价于上面的方法

        return insideSecureHardware;
    }


    // 加解密 AES 安卓版本6.0以上
    @RequiresApi(api = Build.VERSION_CODES.M)
    public void generateAESKey() throws Exception {

        KeyStore keystore = KeyStore.getInstance("AndroidKeyStore");

        keystore.load(null);

        KeyGenerator keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");

        KeyGenParameterSpec.Builder builderSpec = new KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT
        );

        builderSpec
                .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                .setUserAuthenticationRequired(true)
                .setKeySize(256);

        keyGenerator.init(builderSpec.build());
        keyGenerator.generateKey();

        Log.i(TAG, "aes secret key generate complete");

    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    public Cipher getCipher(int purpose, byte[] IV) throws Exception {

        KeyStore keystore = KeyStore.getInstance("AndroidKeyStore");

        keystore.load(null);

        Key key = keystore.getKey(KEY_ALIAS, null);

        Cipher cipher = Cipher.getInstance(
                KeyProperties.KEY_ALGORITHM_AES + "/" +
                        KeyProperties.BLOCK_MODE_CBC + "/" +
                        KeyProperties.ENCRYPTION_PADDING_PKCS7
        );

        switch (purpose) {
            case KeyProperties.PURPOSE_ENCRYPT:
                cipher.init(Cipher.ENCRYPT_MODE, key);
                break;

            case KeyProperties.PURPOSE_DECRYPT:
                cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(IV));
                break;
        }

        return cipher;
    }

    //
    private KeyPair generateRSAKeypairApi18(Context context) throws Exception {

        Calendar localCalendar1 = Calendar.getInstance();

        Calendar localCalendar2;
        (localCalendar2 = Calendar.getInstance()).add(Calendar.YEAR, 20);

        KeyPairGeneratorSpec.Builder builder = new KeyPairGeneratorSpec.Builder(context);
        builder.setAlias(KEY_ALIAS)
                .setSubject(new X500Principal(String.format("CN=%s, OU=%s", KEY_ALIAS, context.getPackageName())))
                .setSerialNumber(BigInteger.ONE)
                .setStartDate(localCalendar1.getTime())
                .setEndDate(localCalendar2.getTime());

        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "AndroidKeyStore");
        generator.initialize(builder.build());
        return generator.generateKeyPair();
    }

    public void haha(Context context) throws Exception {

        // 极限是81个汉字
        String rawData = "一二三四五六七八九十一二三四五六七八九十" +
                "一二三四五六七八九十一二三四五六七八九十" +
                "一二三四五六七八九十一二三四五六七八九十" +
                "一二三四五六七八九十一二三四五六七八九十" +
                "一";


        KeyPair keyPair = generateRSAKeypairApi18(context);

        //PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        //
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] bytes = cipher.doFinal(rawData.getBytes());

        //
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);

        Key key = keyStore.getKey(KEY_ALIAS, null);

        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] bytes1 = cipher.doFinal(bytes);
        Log.wtf("HAHA", "ss=" + new String(bytes1));

    }

}
