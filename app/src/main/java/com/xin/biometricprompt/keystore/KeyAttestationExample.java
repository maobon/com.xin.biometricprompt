/* Copyright 2016, The Android Open Source Project, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.xin.biometricprompt.keystore;

import android.os.Build;
import android.util.Log;

import com.xin.biometricprompt.keystore.sample.AttestationApplicationId;
import com.xin.biometricprompt.keystore.sample.AttestationApplicationId.AttestationPackageInfo;
import com.xin.biometricprompt.keystore.sample.AuthorizationList;
import com.xin.biometricprompt.keystore.sample.ParsedAttestationRecord;
import com.xin.biometricprompt.keystore.sample.RootOfTrust;

import org.bouncycastle.util.encoders.Base64;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Optional;

import static com.xin.biometricprompt.keystore.sample.Constants.GOOGLE_ROOT_CERTIFICATE;
import static com.xin.biometricprompt.keystore.sample.Constants.GOOGLE_SOFT_ECC_ROOT_CERTIFICATE;
import static com.xin.biometricprompt.keystore.sample.Constants.GOOGLE_SOFT_RSA_ROOT_CERTIFICATE;
import static com.xin.biometricprompt.keystore.sample.ParsedAttestationRecord.createParsedAttestationRecord;
import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * This is an illustration of how you can use the Bouncy Castle ASN.1 parser to extract information
 * from an Android attestation data structure. On a secure server that you trust, create similar
 * logic to verify that a key pair has been generated in an Android device. The app on the device
 * must retrieve the key's certificate chain using KeyStore.getCertificateChain(), then send the
 * contents to the trusted server.
 *
 * <p>In this example, the certificate chain includes hard-coded excerpts of each certificate.
 *
 * <p>This example demonstrates the following tasks:
 *
 * <p>1. Loading the certificates from PEM-encoded strings.
 *
 * <p>2. Verifying the certificate chain, up to the root. Note that this example does NOT require
 * the root certificate to appear within Google's list of root certificates. However, if you're
 * verifying the properties of hardware-backed keys on a device that ships with hardware-level key
 * attestation, Android 7.0 (API level 24) or higher, and Google Play services, your production code
 * should enforce this requirement.
 *
 * <p>3. Checking if any certificate in the chain has been revoked or suspended. // ??? 请求网络查询证书吊销状态
 *
 * <p>4. Extracting the attestation extension data from the attestation certificate.
 *
 * <p>5. Verifying (and printing) several important data elements from the attestation extension.
 */

@SuppressWarnings("OptionalUsedAsFieldOrParameterType")
public class KeyAttestationExample {

    private static final String TAG = "KeyAttestationExample";

    /**
     * Google Sample Code
     */
    public static void main(X509Certificate[] certs)
            throws CertificateException, IOException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {

        /*X509Certificate[] certs;
        if (args.length == 1) {
            String certFilesDir = args[0];
            certs = loadCertificates(certFilesDir);
        } else {
            throw new IOException("Expected path to a directory containing certificates as an argument.");
        }*/

        // 证书链校验 使用Google的根证书
        verifyCertificateChain(certs);

        // 解析 Attestation Certificate 证书链的0位证书
        ParsedAttestationRecord parsedAttestationRecord = createParsedAttestationRecord(certs[0]);

        // Attestation 版本与安全等级
        System.out.println("Attestation version: " + parsedAttestationRecord.attestationVersion);
        System.out.println("Attestation Security Level: " + parsedAttestationRecord.attestationSecurityLevel.name());

        // Keymaster 版本与安全等级
        System.out.println("Keymaster Version: " + parsedAttestationRecord.keymasterVersion);
        System.out.println("Keymaster Security Level: " + parsedAttestationRecord.keymasterSecurityLevel.name());

        // 读取生成秘钥对时 设置的挑战值
        System.out.println("Attestation Challenge: " + new String(parsedAttestationRecord.attestationChallenge, UTF_8));

        // 仅有系统应用可以读取该值 其它三方应用返回空
        System.out.println("Unique ID: " + Arrays.toString(parsedAttestationRecord.uniqueId));

        // 软
        System.out.println("Software Enforced Authorization List:");
        AuthorizationList softwareEnforced = parsedAttestationRecord.softwareEnforced;
        printAuthorizationList(softwareEnforced, "\t");

        // 硬 TEE
        System.out.println("TEE Enforced Authorization List:");
        AuthorizationList teeEnforced = parsedAttestationRecord.teeEnforced;
        printAuthorizationList(teeEnforced, "\t");
    }

    private static void printAuthorizationList(AuthorizationList authorizationList, String indent) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.N) return;

        // Detailed explanation of the keys and their values can be found here:
        // https://source.android.com/security/keystore/tags

        printOptional(authorizationList.purpose, indent + "Purpose(s)");
        printOptional(authorizationList.algorithm, indent + "Algorithm");
        printOptional(authorizationList.keySize, indent + "Key Size");
        printOptional(authorizationList.digest, indent + "Digest");
        printOptional(authorizationList.padding, indent + "Padding");
        printOptional(authorizationList.ecCurve, indent + "EC Curve");
        printOptional(authorizationList.rsaPublicExponent, indent + "RSA Public Exponent");
        System.out.println(indent + "Rollback Resistance: " + authorizationList.rollbackResistance);
        printOptional(authorizationList.activeDateTime, indent + "Active DateTime");
        printOptional(authorizationList.originationExpireDateTime, indent + "Origination Expire DateTime");
        printOptional(authorizationList.usageExpireDateTime, indent + "Usage Expire DateTime");
        System.out.println(indent + "No Auth Required: " + authorizationList.noAuthRequired);
        printOptional(authorizationList.userAuthType, indent + "User Auth Type");
        printOptional(authorizationList.authTimeout, indent + "Auth Timeout");
        System.out.println(indent + "Allow While On Body: " + authorizationList.allowWhileOnBody);
        System.out.println(indent + "Trusted User Presence Required: " + authorizationList.trustedUserPresenceRequired);
        System.out.println(indent + "Trusted Confirmation Required: " + authorizationList.trustedConfirmationRequired);
        System.out.println(indent + "Unlocked Device Required: " + authorizationList.unlockedDeviceRequired);
        System.out.println(indent + "All Applications: " + authorizationList.allApplications);
        printOptional(authorizationList.applicationId, indent + "Application ID");
        printOptional(authorizationList.creationDateTime, indent + "Creation DateTime");
        printOptional(authorizationList.origin, indent + "Origin");
        System.out.println(indent + "Rollback Resistant: " + authorizationList.rollbackResistant);

        if (authorizationList.rootOfTrust.isPresent()) {
            System.out.println(indent + "Root Of Trust:");
            printRootOfTrust(authorizationList.rootOfTrust, indent + "\t");
        }

        printOptional(authorizationList.osVersion, indent + "OS Version");
        printOptional(authorizationList.osPatchLevel, indent + "OS Patch Level");

        if (authorizationList.attestationApplicationId.isPresent()) {
            System.out.println(indent + "Attestation Application ID:");
            printAttestationApplicationId(authorizationList.attestationApplicationId, indent + "\t");
        }

        printOptional(authorizationList.attestationApplicationIdBytes, indent + "Attestation Application ID Bytes");
        printOptional(authorizationList.attestationIdBrand, indent + "Attestation ID Brand");
        printOptional(authorizationList.attestationIdDevice, indent + "Attestation ID Device");
        printOptional(authorizationList.attestationIdProduct, indent + "Attestation ID Product");
        printOptional(authorizationList.attestationIdSerial, indent + "Attestation ID Serial");
        printOptional(authorizationList.attestationIdImei, indent + "Attestation ID IMEI");
        printOptional(authorizationList.attestationIdMeid, indent + "Attestation ID MEID");
        printOptional(authorizationList.attestationIdManufacturer, indent + "Attestation ID Manufacturer");
        printOptional(authorizationList.attestationIdModel, indent + "Attestation ID Model");
        printOptional(authorizationList.vendorPatchLevel, indent + "Vendor Patch Level");
        printOptional(authorizationList.bootPatchLevel, indent + "Boot Patch Level");
    }

    private static void printRootOfTrust(Optional<RootOfTrust> rootOfTrust, String indent) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.N) return;

        if (rootOfTrust.isPresent()) {

            System.out.println(indent + "Verified Boot Key: " + Base64.toBase64String(rootOfTrust.get().verifiedBootKey));
            System.out.println(indent + "Device Locked: " + rootOfTrust.get().deviceLocked);

            System.out.println(indent + "Verified Boot State: " + rootOfTrust.get().verifiedBootState.name());
            //System.out.println(indent + "Verified Boot Hash: " + Base64.toBase64String(rootOfTrust.get().verifiedBootHash));
        }
    }

    private static void printAttestationApplicationId(Optional<AttestationApplicationId> attestationApplicationId, String indent) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.N) return;

        if (attestationApplicationId.isPresent()) {
            System.out.println(indent + "Package Infos (<package name>, <version>): ");
            for (AttestationPackageInfo info : attestationApplicationId.get().packageInfos) {
                System.out.println(indent + "\t" + info.packageName + ", " + info.version);
            }
            System.out.println(indent + "Signature Digests:");
            for (byte[] digest : attestationApplicationId.get().signatureDigests) {
                System.out.println(indent + "\t" + Base64.toBase64String(digest));
            }
        }
    }

    private static <T> void printOptional(Optional<T> optional, String caption) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.N) return;

        if (optional.isPresent()) {
            if (optional.get() instanceof byte[]) {
                System.out.println(caption + ": " + Base64.toBase64String((byte[]) optional.get()));
            } else {
                System.out.println(caption + ": " + optional.get());
            }
        }
    }

    private static void verifyCertificateChain(X509Certificate[] certs)
            throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException, IOException {

        X509Certificate parent = certs[certs.length - 1];

        for (int i = certs.length - 1; i >= 0; i--) {
            X509Certificate cert = certs[i];

            // 有效期查询
            // Verify that the certificate has not expired.
            cert.checkValidity();
            cert.verify(parent.getPublicKey());
            parent = cert;

            // 联网查询证书吊销状态
            // Google 的查询地址被墙了 要翻墙才可以正常请求
            /*try {
                CertificateRevocationStatus certStatus = CertificateRevocationStatus.fetchStatus(cert.getSerialNumber());
                if (certStatus != null) {
                    throw new CertificateException("Certificate revocation status is " + certStatus.status.name());
                }
            } catch (IOException e) {
                throw new IOException("Unable to fetch certificate status. Check connectivity.");
            }*/
        }

        // If the attestation is trustworthy and the device ships with hardware-
        // level key attestation, Android 7.0 (API level 24) or higher, and
        // Google Play services, the root certificate should be signed with the
        // Google attestation root key.
        X509Certificate secureRoot = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(GOOGLE_ROOT_CERTIFICATE.getBytes(UTF_8)));

        Log.wtf(TAG, "Hardcode Google Root Cert:"
                + android.util.Base64.encodeToString(secureRoot.getTBSCertificate(), android.util.Base64.DEFAULT));

        /* TBS 格式的证书
         * Gets the DER-encoded certificate information, the tbsCertificate from this certificate.
         * This can be used to verify the signature independently.
         */
        byte[] tbsCertificate = secureRoot.getTBSCertificate(); // X509 TBS 规范的 ASN.1

        /* 单纯 byte数组
         * Returns the encoded form of this certificate. It is assumed that each certificate type
         * would have only a single form of encoding; for example, X.509 certificates would be encoded as ASN.1 DER.
         */
        byte[] encoded = secureRoot.getEncoded(); // Certificate convert to byte array

        // tbsCertificate is not equal with encoded // 不完全相等

        // 硬实现的证书可以取出 TBS
        // 证书链最后一张证书 与 Google的根证书字节数组比对 完全一致为通过
        if (Arrays.equals(secureRoot.getTBSCertificate(), certs[certs.length - 1].getTBSCertificate())) {

            Log.wtf(TAG, "== Google ROOT CERT VERIFIED PASS ==");

            System.out.println(
                    "The root certificate is correct, so this attestation is trustworthy, as long as none of"
                            + " the certificates in the chain have been revoked. A production-level system"
                            + " should check the certificate revocation lists using the distribution points that"
                            + " are listed in the intermediate and root certificates.");

        }

        // 软实现的证书不可以获取TBS
        else {
            Log.wtf(TAG, "== Google ROOT CERT VERIFIED FAILED ==");

            System.out.println(
                    "The root certificate is NOT correct. The attestation was probably generated by"
                            + " software, not in secure hardware. This means that, although the attestation"
                            + " contents are probably valid and correct, there is no proof that they are in fact"
                            + " correct. If you're using a production-level system, you should now treat the"
                            + " properties of this attestation certificate as advisory only, and you shouldn't"
                            + " rely on this attestation certificate to provide security guarantees.");

            // 软实现的证书和算法相关

            // soft impl
            X509Certificate eccSecureRoot = (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(GOOGLE_SOFT_ECC_ROOT_CERTIFICATE.getBytes(UTF_8)));

            X509Certificate rsaSecureRoot = (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(GOOGLE_SOFT_RSA_ROOT_CERTIFICATE.getBytes(UTF_8)));

            if (Arrays.equals(eccSecureRoot.getEncoded(), certs[certs.length - 1].getEncoded())) {
                Log.d(TAG, "ECDSA soft implements verify passed");

            } else if (Arrays.equals(rsaSecureRoot.getEncoded(), certs[certs.length - 1].getEncoded())) {
                Log.d(TAG, "RSA soft implements verify passed");

            }
        }

    /*private static X509Certificate[] loadCertificates(String certFilesDir) throws CertificateException, IOException {
        // Load the attestation certificates from the directory in alphabetic order.

        List<Path> records;
        try (Stream<Path> pathStream = Files.walk(Paths.get(certFilesDir))) {
            records = pathStream.filter(Files::isRegularFile).sorted().collect(Collectors.toList());
        }

        X509Certificate[] certs = new X509Certificate[records.size()];

        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        for (int i = 0; i < records.size(); ++i) {
            byte[] encodedCert = Files.readAllBytes(records.get(i));
            ByteArrayInputStream inputStream = new ByteArrayInputStream(encodedCert);
            certs[i] = (X509Certificate) factory.generateCertificate(inputStream);
        }
        return certs;
    }*/

    }
}
