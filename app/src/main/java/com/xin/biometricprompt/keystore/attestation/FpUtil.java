package com.xin.biometricprompt.keystore.attestation;

import android.annotation.TargetApi;
import android.content.Context;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.text.TextUtils;
import android.util.Log;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Calendar;

import javax.security.auth.x500.X500Principal;

public class FpUtil {

    private static final String TAG = "FpUtil";

    public static byte TAG_ASN1_INT = 0X02;
    public static byte TAG_ASN1_SEQUENCE = 0X30;
    public static byte TAG_ASN1_OCTETSTRING = 0X04;
    public static byte TAG_ASN1_ENUM = 0X0A;

    public static final String KEY_DESCRIPTION_OID = "1.3.6.1.4.1.11129.2.1.17";

    @TargetApi(24)
    public static boolean checkSupport(Context aContext, String keyUUID) {
        try {
            if (null == aContext) {
                return false;
            }

            FingerprintManager pm = (FingerprintManager) aContext.getSystemService(Context.FINGERPRINT_SERVICE);
            if (!pm.isHardwareDetected()) {
                return false;
            }

            Calendar notBefore = Calendar.getInstance();
            Calendar notAfter = Calendar.getInstance();
            notAfter.add(1, 20);

            KeyPairGenerator kpGenerator = KeyPairGenerator.getInstance("EC", "AndroidKeyStore");
            // 使用的算法材料
            KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(keyUUID, 4).setDigests("SHA-256")
                    .setAlgorithmParameterSpec(new ECGenParameterSpec("prime256v1"))
                    .setCertificateSubject(
                            new X500Principal(String.format("CN=%s, OU=%s", keyUUID, aContext.getPackageName())))
                    .setCertificateSerialNumber(BigInteger.ONE).setCertificateNotBefore(notBefore.getTime())
                    .setCertificateNotAfter(notAfter.getTime()).setUserAuthenticationRequired(true);
            // 在android7上可设置setAttestationChallenge
            if (Build.VERSION.SDK_INT > Build.VERSION_CODES.M) {
                builder.setAttestationChallenge(genChallenge());
            }

            // 小米5s实现原因，在某些用例上会造成使用keyStore失败，故不再支持KeyStore
            if (TextUtils.equals("MI 5s", Build.MODEL)) {
                return false;
            }

            kpGenerator.initialize(builder.build());
            kpGenerator.generateKeyPair();

            KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);
            KeyStore.Entry keyEntry = ks.getEntry(keyUUID, null);
            if (keyEntry == null) {
                return false;
            }

            Signature signatureOut = Signature.getInstance("SHA256withECDSA");
            signatureOut.initSign(((KeyStore.PrivateKeyEntry) keyEntry).getPrivateKey());

        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
        return true;
    }

    /**
     * 获取key attestation security level
     */
    public static KeyASecurityType getASecurityLevel(String keyUUID) {
        try {
            Certificate[] certificates = getCertificatesFromChain(keyUUID);
            X509Certificate x509Certificate = (X509Certificate) certificates[0];

            byte[] extensionValue = x509Certificate.getExtensionValue(KEY_DESCRIPTION_OID);
            KeyDescription keyDescription = verifyAttestionExtension(extensionValue);
            if (keyDescription == null) {
                return KeyASecurityType.NOATTESTATION;
            }

            return keyDescription.getAttestationSecurityLevel();

        } catch (Exception e) {
            e.printStackTrace();
        }
        return KeyASecurityType.NOATTESTATION;
    }

    /**
     * 获取证书
     */
    private static Certificate[] getCertificatesFromChain(String keyUUID) {
        try {
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);

            Certificate[] certificates = keyStore.getCertificateChain(keyUUID);
            return certificates;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 挑战值
     */
    private static byte[] genChallenge() {
        SecureRandom random = new SecureRandom();
        byte[] challenge = new byte[32];
        random.nextBytes(challenge);
        return challenge;
    }

    /**
     * 解析attestation
     */
    private static KeyDescription verifyAttestionExtension(byte[] extension) {
        KeyDescription description = new KeyDescription();
        try {
            if (extension == null || extension.length == 0) {
                return null;
            }
            ByteBuffer bufStream = ByteBuffer.wrap(extension);
            bufStream.order(ByteOrder.LITTLE_ENDIAN);

            // verify root
            byte rootTag = bufStream.get();
            int rootLength = getASN1Length(bufStream);
            if (!(rootTag == TAG_ASN1_OCTETSTRING && bufStream.hasRemaining() && bufStream.remaining() == rootLength)) {
                Log.e(TAG, "is not attestation extension by root , maybe not der");
                return null;
            }

            // verify root sequence
            byte rootSequenceTag = bufStream.get();
            int rootSequenceLength = getASN1Length(bufStream);
            if (!(rootSequenceTag == TAG_ASN1_SEQUENCE && bufStream.hasRemaining())) {
                Log.e(TAG, "is not attestation extension by root sequence");
                return null;
            }

            // verify attestation version
            byte attestationVersionTag = bufStream.get();
            int attestationVersionLength = getASN1Length(bufStream);
            byte[] attestationVersionValue = new byte[attestationVersionLength];
            bufStream.get(attestationVersionValue);
            if (!(attestationVersionTag == TAG_ASN1_INT)) {
                Log.e(TAG, "is not attestion extension by attestation version");
                return null;
            }
            description.setAttestationVersion(attestationVersionValue[0] & 0xff);

            // verify attestation security
            byte attestationSecurityTag = bufStream.get();
            int attestationSecurityLength = getASN1Length(bufStream);
            byte[] attestationSecurityValue = new byte[attestationSecurityLength];
            bufStream.get(attestationSecurityValue);
            if (!(attestationSecurityTag == TAG_ASN1_ENUM)) {
                Log.e(TAG, "is not attestion extension by tmp1");
                return null;
            }
            description.setAttestationSecurityLevel(attestationSecurityValue[0] & 0xff);

            // verify keymaster version
            byte keymasterVersionTag = bufStream.get();
            int keymasterVersionLength = getASN1Length(bufStream);
            if (keymasterVersionLength != 0) {
                byte[] keymasterVersionValue = new byte[keymasterVersionLength];
                bufStream.get(keymasterVersionValue);
                if (!(keymasterVersionTag == TAG_ASN1_INT)) {
                    Log.e(TAG, "is not attestion extension by tmp2");
                    return null;
                }
                description.setKeymasterVersion(keymasterVersionValue[0] & 0xff);
            }

            // verify keymaster security
            byte keymasterSecurityTag = bufStream.get();
            int keymasterSecurityLength = getASN1Length(bufStream);
            byte[] keymasterSecurityValue = new byte[keymasterSecurityLength];
            bufStream.get(keymasterSecurityValue);
            if (!(keymasterSecurityTag == TAG_ASN1_ENUM)) {
                Log.e(TAG, "is not attestion extension by keymaster security");
                return null;
            }
            description.setKeymasterSecurityLevel(keymasterSecurityValue[0] & 0xff);

            // verify challenge
            byte challengeTag = bufStream.get();
            int challengeLength = getASN1Length(bufStream);
            if (challengeLength != 0) {
                byte[] challengeValue = new byte[challengeLength];
                bufStream.get(challengeValue);
                if (!(challengeTag == TAG_ASN1_OCTETSTRING)) {
                    Log.e(TAG, "is not attestion extension by challenge");
                    return null;
                }
                description.setAttestationChallenge(challengeValue);
            }

            // verify tmp
            byte tmp2Tag = bufStream.get();
            int tmp2Length = getASN1Length(bufStream);
            if (tmp2Length != 0) {
                byte[] tmp2Value = new byte[tmp2Length];
                bufStream.get(tmp2Value);
                if (!(tmp2Tag == TAG_ASN1_OCTETSTRING)) {
                    Log.e(TAG, "is not attestion extension by tmp2");
                    return null;
                }
            }

            // verify swenforced
            byte swTag = bufStream.get();
            int swLength = getASN1Length(bufStream);
            if (swLength != 0) {
                byte[] swValue = new byte[swLength];
                bufStream.get(swValue);
                if (!(swTag == TAG_ASN1_SEQUENCE)) {
                    Log.e(TAG, "is not attestion extension by sw");
                    return null;
                }
            }

            // verify tee
            byte teeTag = bufStream.get();
            int teeLength = getASN1Length(bufStream);
            if (teeLength != 0) {
                byte[] teeValue = new byte[teeLength];
                bufStream.get(teeValue);
                if (!(teeTag == TAG_ASN1_SEQUENCE)) {
                    Log.e(TAG, "is not attestion extension by tee");
                    return null;
                }
            }
            return description;
        } catch (Exception e) {
            Log.e(TAG, "verifyAttestionExtension:" + e.getMessage());
        }
        return null;

    }

    private static int getASN1Length(ByteBuffer buf) {
        Log.d(TAG, "getASN1Length");
        byte tmpLength = buf.get();
        if ((tmpLength & 0x80) == 0) {
            return tmpLength;
        } else {
            int lengthLength = tmpLength & 0x7f;
            if (lengthLength > 4) {
                // extension der will not be large than 65535
                return -1;
            }
            byte[] tmpLengths = new byte[lengthLength];
            buf.get(tmpLengths);
            return byteArrayToInt(tmpLengths);
        }
    }

    private static int byteArrayToInt(byte[] b) {
        int length = b.length;
        int value = 0;
        for (int i = 0; i < length; i++) {
            value = value | ((b[i] & 0xff) << (length - 1 - i) * 8);
        }
        return value;
    }

}
