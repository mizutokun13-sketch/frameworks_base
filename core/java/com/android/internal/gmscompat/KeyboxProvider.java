/*
 * Copyright (C) 2026 The Android Open Source Project
 * SPDX-License-Identifier: Apache-2.0
 */

package com.android.internal.gmscompat;

import android.os.Build;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;

import com.android.internal.org.bouncycastle.asn1.ASN1Boolean;
import com.android.internal.org.bouncycastle.asn1.ASN1Encodable;
import com.android.internal.org.bouncycastle.asn1.ASN1EncodableVector;
import com.android.internal.org.bouncycastle.asn1.ASN1Enumerated;
import com.android.internal.org.bouncycastle.asn1.ASN1Integer;
import com.android.internal.org.bouncycastle.asn1.ASN1Sequence;
import com.android.internal.org.bouncycastle.asn1.DERNull;
import com.android.internal.org.bouncycastle.asn1.DEROctetString;
import com.android.internal.org.bouncycastle.asn1.DERSequence;
import com.android.internal.org.bouncycastle.asn1.DERSet;
import com.android.internal.org.bouncycastle.asn1.DERTaggedObject;
import com.android.internal.org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import com.android.internal.org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import com.android.internal.org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import com.android.internal.org.bouncycastle.asn1.sec.ECPrivateKeyStructure;
import com.android.internal.org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import com.android.internal.org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import com.android.internal.org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import com.android.internal.org.bouncycastle.jce.X509Principal;
import com.android.internal.org.bouncycastle.x509.X509V3CertificateGenerator;

import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserFactory;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileReader;
import java.io.StringReader;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Keybox Attestation Provider for Play Integrity & Hardware Keystore Emulation.
 * Reads OEM keybox.xml and generates genuine Google-rooted X.509 certificate chains.
 */
public final class KeyboxProvider {
    private static final String TAG = "KeyboxProvider";
    private static final String ATTESTATION_OID = "1.3.6.1.4.1.11129.2.1.17";

    private static final String KEYBOX_PATH = "/data/vendor/keybox/keybox.xml";

    private static class KeyboxData {
        PrivateKey privateKey;
        List<X509Certificate> certificates = new ArrayList<>();
    }

    private static final Map<String, KeyboxData> sKeyboxes = new ConcurrentHashMap<>();
    private static final Map<String, Certificate[]> sEmulatedChains = new ConcurrentHashMap<>();
    private static long sLastModified = 0;

    private KeyboxProvider() {}

    public static synchronized void ensureInitialized() {
        File f = new File(KEYBOX_PATH);
        if (!f.exists() || !f.canRead()) {
            return;
        }
        long mtime = f.lastModified();
        if (!sKeyboxes.isEmpty() && mtime == sLastModified) {
            return;
        }
        sKeyboxes.clear();
        sEmulatedChains.clear();
        Log.i(TAG, "Loading keybox from " + KEYBOX_PATH);
        if (loadKeyboxFromFile(f)) {
            sLastModified = mtime;
            Log.i(TAG, "Successfully loaded Keybox! Total algorithms: " + sKeyboxes.size());
        } else {
            Log.w(TAG, "Failed to parse keybox at " + KEYBOX_PATH);
        }
    }

    public static boolean isKeyboxAvailable() {
        ensureInitialized();
        return !sKeyboxes.isEmpty();
    }

    public static boolean hasEmulatedChain(String alias) {
        return alias != null && sEmulatedChains.containsKey(alias);
    }

    public static Certificate[] getEmulatedChain(String alias) {
        if (alias == null) return null;
        return sEmulatedChains.get(alias);
    }

    public static void removeEmulatedChain(String alias) {
        if (alias != null) {
            sEmulatedChains.remove(alias);
        }
    }

    private static boolean isGmsOrPlayStoreCaller() {
        try {
            String pkg = android.app.ActivityThread.currentPackageName();
            String proc = android.app.ActivityThread.currentProcessName();
            if (pkg != null && (pkg.equals("com.google.android.gms")
                    || pkg.equals("com.android.vending")
                    || pkg.equals("com.google.android.gsf"))) {
                return true;
            }
            if (proc != null && (proc.contains("com.google.android.gms")
                    || proc.contains("com.android.vending")
                    || proc.contains("com.google.android.gsf"))) {
                return true;
            }
        } catch (Throwable ignored) {}
        return false;
    }

    private static String getHwcfgField(String key, String fallback) {
        try {
            String val = android.os.SystemProperties.get("sys.hwcfg." + key, "");
            if (val == null || val.trim().isEmpty()) {
                val = android.os.SystemProperties.get("persist.sys.hwcfg." + key, "");
            }
            if (val != null && !val.trim().isEmpty()) {
                return val.trim();
            }
            String[] dirs = { "/data/vendor/hwcfg/", "/data/vendor/hwcfg/Utils/" };
            for (String dir : dirs) {
                File f = new File(dir + key);
                if (f.exists() && f.canRead()) {
                    try (java.io.BufferedReader br = new java.io.BufferedReader(new FileReader(f))) {
                        String line = br.readLine();
                        if (line != null && !line.trim().isEmpty()) {
                            return line.trim();
                        }
                    }
                }
            }
        } catch (Throwable ignored) {}
        return fallback != null ? fallback : "";
    }

    private static String getActiveProfileIdentity() {
        String seed = getHwcfgField("seed", "");
        String androidId = getHwcfgField("android_id", "");
        String brand = getHwcfgField("brand", Build.BRAND);
        String device = getHwcfgField("device", Build.DEVICE);
        String model = getHwcfgField("model", Build.MODEL);
        String serial = getHwcfgField("serial", "");
        String fp = getHwcfgField("fingerprint", Build.FINGERPRINT);
        return seed + "|" + androidId + "|" + brand + "|" + device + "|" + model + "|" + serial + "|" + fp;
    }

    private static byte[] sha256Bytes(String input) {
        try {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
            return md.digest(input.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        } catch (Exception e) {
            byte[] out = new byte[32];
            byte[] src = input.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            for (int i = 0; i < out.length; i++) {
                out[i] = (byte) (src[i % src.length] ^ (i * 31 + 17));
            }
            return out;
        }
    }

    private static BigInteger derivePositiveSerial(String domain, String identity) {
        byte[] hash = sha256Bytes(domain + "|" + identity);
        byte[] serialBytes = new byte[16];
        System.arraycopy(hash, 0, serialBytes, 0, 16);
        serialBytes[0] &= 0x7F;
        if (serialBytes[0] == 0) {
            serialBytes[0] = 0x42;
        }
        return new BigInteger(1, serialBytes);
    }

    private static X509Certificate buildDynamicIntermediateCert(
            X509Certificate origInter, PrivateKey signKey, boolean isEc, String profileIdentity) {
        try {
            byte[] tokenHash = sha256Bytes("hwcfg/inter_subject/" + profileIdentity);
            StringBuilder hexId = new StringBuilder();
            for (int i = 0; i < 8; i++) {
                hexId.append(String.format("%02x", tokenHash[i] & 0xff));
            }
            X509Principal dynamicSubject = new X509Principal(
                    "O=Android, OU=Android Keystore, CN=Android Keystore Software Attestation Intermediate " + hexId);

            X509V3CertificateGenerator gen = new X509V3CertificateGenerator();
            gen.setSerialNumber(derivePositiveSerial("hwcfg/inter_serial", profileIdentity));
            gen.setIssuerDN(new X509Principal(origInter.getIssuerX500Principal().getEncoded()));
            gen.setNotBefore(origInter.getNotBefore());
            gen.setNotAfter(origInter.getNotAfter());
            gen.setSubjectDN(dynamicSubject);
            gen.setPublicKey(origInter.getPublicKey());
            gen.setSignatureAlgorithm(isEc ? "SHA256withECDSA" : "SHA256withRSA");
            return gen.generate(signKey);
        } catch (Throwable t) {
            return origInter;
        }
    }

    public static void onKeyGenerated(String alias, PublicKey publicKey, byte[] challenge,
                                   int purposes, int keySize, boolean isEc) {
        if (alias == null || publicKey == null || challenge == null) return;
        ensureInitialized();

        String algoKey = isEc ? "ecdsa" : "rsa";
        KeyboxData kb = sKeyboxes.get(algoKey);
        if (kb == null) {
            // Fallback to whichever keybox is present
            for (KeyboxData data : sKeyboxes.values()) {
                kb = data;
                break;
            }
        }

        if (kb == null || kb.certificates.isEmpty() || kb.privateKey == null) {
            Log.e(TAG, "No keybox available to generate attestation certificate for " + alias);
            return;
        }

        try {
            boolean isGms = isGmsOrPlayStoreCaller();
            String profileIdentity = isGms ? "" : getActiveProfileIdentity();

            X509Certificate issuerCert = isGms
                    ? kb.certificates.get(0)
                    : buildDynamicIntermediateCert(kb.certificates.get(0), kb.privateKey, isEc, profileIdentity);

            X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();

            BigInteger leafSerial = isGms
                    ? BigInteger.valueOf(System.currentTimeMillis())
                    : derivePositiveSerial("hwcfg/leaf_serial/" + alias, profileIdentity);
            certGen.setSerialNumber(leafSerial);
            certGen.setIssuerDN(new X509Principal(issuerCert.getSubjectX500Principal().getEncoded()));
            certGen.setNotBefore(new Date(System.currentTimeMillis() - 120000)); // 2 min in past
            certGen.setNotAfter(new Date(System.currentTimeMillis() + 365L * 24 * 3600 * 1000)); // 1 year
            certGen.setSubjectDN(new X509Principal("CN=Android Keystore Key"));
            certGen.setPublicKey(publicKey);
            certGen.setSignatureAlgorithm(isEc ? "SHA256withECDSA" : "SHA256withRSA");

            DERSequence attestationExtension = buildAttestationExtension(
                    challenge, isEc, keySize, purposes, isGms, profileIdentity);
            certGen.addExtension(ATTESTATION_OID, false, attestationExtension);

            X509Certificate leafCert = certGen.generate(kb.privateKey);

            Certificate[] fullChain = new Certificate[1 + kb.certificates.size()];
            fullChain[0] = leafCert;
            fullChain[1] = issuerCert;
            for (int i = 1; i < kb.certificates.size(); i++) {
                fullChain[i + 1] = kb.certificates.get(i);
            }

            sEmulatedChains.put(alias, fullChain);
            Log.i(TAG, "[ATTESTATION SUCCESS] Generated hardware certificate chain for alias=" + alias
                    + " isGms=" + isGms + " challengeLen=" + challenge.length + " certChainLen=" + fullChain.length);
        } catch (Exception e) {
            Log.e(TAG, "Failed to generate emulated attestation certificate for alias=" + alias, e);
        }
    }

    private static DERSequence buildAttestationExtension(
            byte[] challenge, boolean isEc, int keySize, int purposes, boolean isGms, String profileIdentity) {
        // 1. RootOfTrust
        byte[] verifiedBootKey;
        byte[] verifiedBootHash;
        if (isGms || profileIdentity == null || profileIdentity.isEmpty()) {
            verifiedBootKey = sha256Bytes("google/panther/avb/key");
            verifiedBootHash = sha256Bytes("google/panther/vbmeta/AP4A.250605.005");
        } else {
            verifiedBootKey = sha256Bytes("hwcfg/avb/key/" + profileIdentity);
            verifiedBootHash = sha256Bytes("hwcfg/vbmeta/hash/" + profileIdentity);
        }

        ASN1EncodableVector rotVec = new ASN1EncodableVector();
        rotVec.add(new DEROctetString(verifiedBootKey));  // verifiedBootKey
        rotVec.add(ASN1Boolean.TRUE);                      // deviceLocked = true
        rotVec.add(new ASN1Enumerated(0));                 // verifiedBootState = Verified (0)
        rotVec.add(new DEROctetString(verifiedBootHash));  // verifiedBootHash
        DERSequence rootOfTrust = new DERSequence(rotVec);

        // 2. TEE Enforced AuthorizationList
        ASN1EncodableVector teeVec = new ASN1EncodableVector();

        // Tag 1: Purpose (SET OF INTEGER)
        ASN1EncodableVector purposeVec = new ASN1EncodableVector();
        if (purposes != 0) {
            if ((purposes & KeyProperties.PURPOSE_SIGN) != 0) purposeVec.add(new ASN1Integer(2));
            if ((purposes & KeyProperties.PURPOSE_VERIFY) != 0) purposeVec.add(new ASN1Integer(3));
            if ((purposes & KeyProperties.PURPOSE_ENCRYPT) != 0) purposeVec.add(new ASN1Integer(0));
            if ((purposes & KeyProperties.PURPOSE_DECRYPT) != 0) purposeVec.add(new ASN1Integer(1));
            if ((purposes & KeyProperties.PURPOSE_WRAP_KEY) != 0) purposeVec.add(new ASN1Integer(5));
            if ((purposes & KeyProperties.PURPOSE_AGREE_KEY) != 0) purposeVec.add(new ASN1Integer(6));
            if ((purposes & KeyProperties.PURPOSE_ATTEST_KEY) != 0) purposeVec.add(new ASN1Integer(7));
        } else {
            purposeVec.add(new ASN1Integer(2)); // Default SIGN
            purposeVec.add(new ASN1Integer(3)); // Default VERIFY
        }
        teeVec.add(new DERTaggedObject(true, 1, new DERSet(purposeVec)));

        // Tag 2: Algorithm (INTEGER): 1 = RSA, 3 = EC
        teeVec.add(new DERTaggedObject(true, 2, new ASN1Integer(isEc ? 3 : 1)));

        // Tag 3: KeySize (INTEGER)
        int effectiveKeySize = keySize > 0 ? keySize : (isEc ? 256 : 2048);
        teeVec.add(new DERTaggedObject(true, 3, new ASN1Integer(effectiveKeySize)));

        // Tag 5: Digest (SET OF INTEGER): 4 = SHA-256
        ASN1EncodableVector digestVec = new ASN1EncodableVector();
        digestVec.add(new ASN1Integer(4)); // SHA-256
        teeVec.add(new DERTaggedObject(true, 5, new DERSet(digestVec)));

        // Tag 10: EcCurve (INTEGER): 1 = P-256 (secp256r1)
        if (isEc) {
            teeVec.add(new DERTaggedObject(true, 10, new ASN1Integer(1)));
        }

        // Tag 200: RSA Public Exponent (INTEGER)
        if (!isEc) {
            teeVec.add(new DERTaggedObject(true, 200, new ASN1Integer(BigInteger.valueOf(65537))));
        }

        // Tag 503: NoAuthRequired (NULL)
        teeVec.add(new DERTaggedObject(true, 503, DERNull.INSTANCE));

        // Tag 701: CreationDateTime (INTEGER - ms)
        teeVec.add(new DERTaggedObject(true, 701, new ASN1Integer(System.currentTimeMillis())));

        // Tag 702: Origin (INTEGER): 0 = Generated
        teeVec.add(new DERTaggedObject(true, 702, new ASN1Integer(0)));

        // Tag 704: RootOfTrust (SEQUENCE)
        teeVec.add(new DERTaggedObject(true, 704, rootOfTrust));

        // Tag 705: OS Version (INTEGER): 130000 for Android 13
        int osVersion = 130000;
        try {
            int releaseInt = Integer.parseInt(Build.VERSION.RELEASE);
            osVersion = releaseInt * 10000;
        } catch (Exception ignored) {}
        teeVec.add(new DERTaggedObject(true, 705, new ASN1Integer(osVersion)));

        // Tag 706: OS PatchLevel (INTEGER): e.g. 202506
        int patchLevel = 202506;
        try {
            String patchStr = (isGms ? Build.VERSION.SECURITY_PATCH : getHwcfgField("securitypatch", Build.VERSION.SECURITY_PATCH)).replace("-", "");
            if (patchStr.length() >= 6) {
                patchLevel = Integer.parseInt(patchStr.substring(0, 6));
            }
        } catch (Exception ignored) {}
        teeVec.add(new DERTaggedObject(true, 706, new ASN1Integer(patchLevel)));

        // Tags 710..717: Device identity tags matching active WantSpoof profile for non-GMS apps
        if (!isGms) {
            String brand = getHwcfgField("brand", Build.BRAND);
            String device = getHwcfgField("device", Build.DEVICE);
            String product = getHwcfgField("name", Build.PRODUCT);
            String serial = getHwcfgField("serial", "");
            String model = getHwcfgField("model", Build.MODEL);
            String manufacturer = getHwcfgField("manufacturer", brand);

            if (!brand.isEmpty()) {
                teeVec.add(new DERTaggedObject(true, 710,
                        new DEROctetString(brand.getBytes(java.nio.charset.StandardCharsets.UTF_8))));
            }
            if (!device.isEmpty()) {
                teeVec.add(new DERTaggedObject(true, 711,
                        new DEROctetString(device.getBytes(java.nio.charset.StandardCharsets.UTF_8))));
            }
            if (!product.isEmpty()) {
                teeVec.add(new DERTaggedObject(true, 712,
                        new DEROctetString(product.getBytes(java.nio.charset.StandardCharsets.UTF_8))));
            }
            if (!serial.isEmpty()) {
                teeVec.add(new DERTaggedObject(true, 713,
                        new DEROctetString(serial.getBytes(java.nio.charset.StandardCharsets.UTF_8))));
            }
            if (!model.isEmpty()) {
                teeVec.add(new DERTaggedObject(true, 716,
                        new DEROctetString(model.getBytes(java.nio.charset.StandardCharsets.UTF_8))));
            }
            if (!manufacturer.isEmpty()) {
                teeVec.add(new DERTaggedObject(true, 717,
                        new DEROctetString(manufacturer.getBytes(java.nio.charset.StandardCharsets.UTF_8))));
            }
        }

        // Tag 718: VendorPatchLevel (INTEGER)
        teeVec.add(new DERTaggedObject(true, 718, new ASN1Integer(patchLevel)));

        // Tag 719: BootPatchLevel (INTEGER)
        teeVec.add(new DERTaggedObject(true, 719, new ASN1Integer(patchLevel)));

        DERSequence teeEnforced = new DERSequence(teeVec);

        // 3. Software Enforced AuthorizationList
        ASN1EncodableVector swVec = new ASN1EncodableVector();
        ASN1Encodable aaid = buildAttestationApplicationId();
        if (aaid != null) {
            // Tag 709 schema: [709] EXPLICIT OCTET STRING
            // aaid is already a DEROctetString (from buildAttestationApplicationId)
            swVec.add(new DERTaggedObject(true, 709, aaid));
        }
        DERSequence swEnforced = new DERSequence(swVec);

        // KeyDescription ::= SEQUENCE
        ASN1EncodableVector keyDescVec = new ASN1EncodableVector();
        keyDescVec.add(new ASN1Integer(200)); // attestationVersion = 200 (KeyMint 2.0)
        keyDescVec.add(new ASN1Enumerated(1)); // attestationSecurityLevel = TrustedEnvironment (1)
        keyDescVec.add(new ASN1Integer(200)); // keymasterVersion = 200 (KeyMint 2.0)
        keyDescVec.add(new ASN1Enumerated(1)); // keymasterSecurityLevel = TrustedEnvironment (1)
        keyDescVec.add(new DEROctetString(challenge)); // attestationChallenge
        keyDescVec.add(new DEROctetString(new byte[0])); // uniqueId
        keyDescVec.add(swEnforced);
        keyDescVec.add(teeEnforced);

        return new DERSequence(keyDescVec);
    }

    private static ASN1Encodable buildAttestationApplicationId() {
        try {
            android.app.Application app = android.app.ActivityThread.currentApplication();
            String pkgName = android.app.ActivityThread.currentPackageName();
            if (pkgName == null || pkgName.isEmpty()) {
                if (app != null) {
                    pkgName = app.getPackageName();
                }
            }
            if (pkgName == null || pkgName.isEmpty()) {
                pkgName = "com.google.android.gms";
            }

            long versionCode = 1;
            List<byte[]> certDigests = new ArrayList<>();

            if (app != null) {
                try {
                    android.content.pm.PackageManager pm = app.getPackageManager();
                    android.content.pm.PackageInfo pi = pm.getPackageInfo(pkgName,
                            android.content.pm.PackageManager.GET_SIGNING_CERTIFICATES);
                    versionCode = pi.getLongVersionCode();
                    android.content.pm.SigningInfo si = pi.signingInfo;
                    if (si != null) {
                        android.content.pm.Signature[] sigs = si.getApkContentsSigners();
                        if (sigs == null || sigs.length == 0) {
                            sigs = si.getSigningCertificateHistory();
                        }
                        if (sigs != null && sigs.length > 0) {
                            java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
                            for (android.content.pm.Signature sig : sigs) {
                                certDigests.add(md.digest(sig.toByteArray()));
                            }
                        }
                    }
                } catch (Throwable t) {
                    Log.w(TAG, "Could not query PackageManager for AAID of " + pkgName, t);
                }
            }

            if (certDigests.isEmpty()) {
                certDigests.add(new byte[32]);
            }

            // AttestationPackageInfo ::= SEQUENCE { packageName OCTET STRING, version INTEGER }
            ASN1EncodableVector pkgInfoVec = new ASN1EncodableVector();
            pkgInfoVec.add(new DEROctetString(pkgName.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
            pkgInfoVec.add(new ASN1Integer(versionCode));
            DERSequence pkgInfoSeq = new DERSequence(pkgInfoVec);

            // packageInfoRecords SET OF AttestationPackageInfo
            ASN1EncodableVector pkgRecordsVec = new ASN1EncodableVector();
            pkgRecordsVec.add(pkgInfoSeq);
            DERSet pkgRecordsSet = new DERSet(pkgRecordsVec);

            // signatureDigests SET OF OCTET STRING
            ASN1EncodableVector sigDigestsVec = new ASN1EncodableVector();
            for (byte[] digest : certDigests) {
                sigDigestsVec.add(new DEROctetString(digest));
            }
            DERSet sigDigestsSet = new DERSet(sigDigestsVec);

            // AttestationApplicationId ::= SEQUENCE { packageInfoRecords, signatureDigests }
            ASN1EncodableVector aaidVec = new ASN1EncodableVector();
            aaidVec.add(pkgRecordsSet);
            aaidVec.add(sigDigestsSet);
            DERSequence aaidSeq = new DERSequence(aaidVec);

            return new DEROctetString(aaidSeq.getEncoded());
        } catch (Throwable t) {
            Log.e(TAG, "Failed to construct AttestationApplicationId", t);
            return null;
        }
    }

    private static boolean loadKeyboxFromFile(File file) {
        try {
            XmlPullParser parser = XmlPullParserFactory.newInstance().newPullParser();
            parser.setInput(new FileReader(file));

            String currentAlgo = null;
            String currentPrivKeyPem = null;
            List<String> currentCerts = new ArrayList<>();

            int eventType = parser.getEventType();
            while (eventType != XmlPullParser.END_DOCUMENT) {
                String tagName = parser.getName();
                switch (eventType) {
                    case XmlPullParser.START_TAG:
                        if ("Key".equalsIgnoreCase(tagName)) {
                            currentAlgo = parser.getAttributeValue(null, "algorithm");
                            currentPrivKeyPem = null;
                            currentCerts.clear();
                        } else if ("PrivateKey".equalsIgnoreCase(tagName)) {
                            currentPrivKeyPem = parser.nextText();
                        } else if ("Certificate".equalsIgnoreCase(tagName)) {
                            String certText = parser.nextText();
                            if (certText != null && !certText.trim().isEmpty()) {
                                currentCerts.add(certText.trim());
                            }
                        }
                        break;
                    case XmlPullParser.END_TAG:
                        if ("Key".equalsIgnoreCase(tagName) && currentAlgo != null && currentPrivKeyPem != null) {
                            parseAndStoreKeybox(currentAlgo, currentPrivKeyPem, currentCerts);
                        }
                        break;
                }
                eventType = parser.next();
            }
            return !sKeyboxes.isEmpty();
        } catch (Exception e) {
            Log.e(TAG, "Error parsing keybox XML: " + file.getAbsolutePath(), e);
            return false;
        }
    }

    private static void parseAndStoreKeybox(String algo, String privKeyPem, List<String> certPems) {
        try {
            String cleanAlgo = algo.toLowerCase();
            boolean isEc = cleanAlgo.contains("ec");

            byte[] derBytes = decodePem(privKeyPem);
            PrivateKey privateKey = parsePrivateKey(derBytes, isEc);

            CertificateFactory certFactory;
            try {
                certFactory = CertificateFactory.getInstance("X.509", new com.android.internal.org.bouncycastle.jce.provider.BouncyCastleProvider());
            } catch (Exception e) {
                certFactory = CertificateFactory.getInstance("X.509");
            }
            List<X509Certificate> certificates = new ArrayList<>();
            for (String certPem : certPems) {
                byte[] certDer = decodePem(certPem);
                X509Certificate cert = (X509Certificate) certFactory.generateCertificate(
                        new ByteArrayInputStream(certDer));
                if (cert != null) {
                    certificates.add(cert);
                }
            }

            if (privateKey != null && !certificates.isEmpty()) {
                KeyboxData data = new KeyboxData();
                data.privateKey = privateKey;
                data.certificates = certificates;
                sKeyboxes.put(isEc ? "ecdsa" : "rsa", data);
                Log.i(TAG, "Registered Keybox for algo=" + (isEc ? "ecdsa" : "rsa")
                        + " with " + certificates.size() + " certificates.");
            }
        } catch (Exception e) {
            Log.e(TAG, "Failed to parse keybox entry for algo=" + algo, e);
        }
    }

    private static byte[] decodePem(String pem) {
        String clean = pem.replaceAll("-----BEGIN [A-Z ]+-----", "")
                          .replaceAll("-----END [A-Z ]+-----", "")
                          .replaceAll("\\s+", "");
        return Base64.decode(clean, Base64.DEFAULT);
    }

    private static PrivateKey parsePrivateKey(byte[] derBytes, boolean isEc) throws Exception {
        if (isEc) {
            // Check if it's SEC1 (ECPrivateKeyStructure) or PKCS#8
            try {
                ASN1Sequence seq = (ASN1Sequence) ASN1Sequence.fromByteArray(derBytes);
                ECPrivateKeyStructure ecPriv = new ECPrivateKeyStructure(seq);
                AlgorithmIdentifier algId = new AlgorithmIdentifier(
                        X9ObjectIdentifiers.id_ecPublicKey,
                        SECObjectIdentifiers.secp256r1);
                PrivateKeyInfo pki = new PrivateKeyInfo(algId, ecPriv);
                return KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(pki.getEncoded()));
            } catch (Exception e) {
                // Fallback to standard PKCS#8
                return KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(derBytes));
            }
        } else {
            // Check if it's PKCS#1 or PKCS#8
            try {
                ASN1Sequence seq = (ASN1Sequence) ASN1Sequence.fromByteArray(derBytes);
                RSAPrivateKey rsaPriv = RSAPrivateKey.getInstance(seq);
                AlgorithmIdentifier algId = new AlgorithmIdentifier(
                        PKCSObjectIdentifiers.rsaEncryption,
                        DERNull.INSTANCE);
                PrivateKeyInfo pki = new PrivateKeyInfo(algId, rsaPriv);
                return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(pki.getEncoded()));
            } catch (Exception e) {
                // Fallback to standard PKCS#8
                return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(derBytes));
            }
        }
    }
}
