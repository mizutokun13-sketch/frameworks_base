/*
 * Copyright (C) 2021 The LineageOS Project
 *           (C) 2023-2024 The DerpFest Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.internal.gmscompat;

import android.app.Application;
import android.content.Context;
import android.os.Binder;
import android.os.Build;
import android.os.Environment;
import android.os.SystemProperties;
import android.text.TextUtils;
import android.util.Log;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.Iterator;

/** @hide */
public final class AttestationHooks {
    private static final String TAG = "AttestationHooks";
    private static final boolean DEBUG = Log.isLoggable(TAG, Log.DEBUG);

    private static final String PACKAGE_GMS = "com.google.android.gms";
    private static final String PACKAGE_FINSKY = "com.android.vending";
    private static final String PACKAGE_GSF = "com.google.android.gsf";
    private static final String PROCESS_UNSTABLE = "com.google.android.gms.unstable";
    private static final String DATA_FILE = "gms_certified_props.json";

    private static volatile boolean sIsGms = false;
    private static volatile boolean sIsUnstable = false;

    private AttestationHooks() {}

    /**
     * Khởi tạo trước khi Application.onCreate() của tiến trình được gọi.
     */
    public static void initApplicationBeforeOnCreate(Context context) {
        if (context == null) return;

        final String packageName = context.getPackageName();
        final String processName = Application.getProcessName();

        if (TextUtils.isEmpty(packageName) || TextUtils.isEmpty(processName)) return;

        final boolean spoofGms = SystemProperties.getBoolean("persist.sys.spoof.gms", true);

        // =========================================================================
        // NHÁNH 1: DÀNH RIÊNG CHO GMS & CH PLAY (PLAY INTEGRITY CERTIFICATION)
        // =========================================================================
        if (PACKAGE_GMS.equals(packageName) || PACKAGE_FINSKY.equals(packageName) || PACKAGE_GSF.equals(packageName)) {
            sIsGms = true;

            if (PROCESS_UNSTABLE.equals(processName) || processName.contains("unstable")) {
                sIsUnstable = true;
                if (spoofGms) {
                    setGmsCertifiedProps();
                }
            }

            if (spoofGms) {
                setBuildField("TIME", String.valueOf(System.currentTimeMillis()));
            }
            return;
        }

        // =========================================================================
        // NHÁNH 2: DÀNH CHO TẤT CẢ APP BÊN THỨ 3 (DÙNG PROFILE TỪ WANTSPOOF / HWCFG)
        // =========================================================================
        if (!"com.wantphone.wantspoof".equals(packageName)) {
            spoofAppBuildFields(context);
        }
    }

    private static void setGmsCertifiedProps() {
        File dataFile = new File(Environment.getDataSystemDirectory(), DATA_FILE);
        String savedProps = readFromFile(dataFile);

        if (TextUtils.isEmpty(savedProps)) {
            File sysFile = new File("/system/etc/gms_certified_props.json");
            if (sysFile.exists()) {
                savedProps = readFromFile(sysFile);
            }
        }

        if (TextUtils.isEmpty(savedProps)) {
            File vendorFile = new File("/vendor/etc/gms_certified_props.json");
            if (vendorFile.exists()) {
                savedProps = readFromFile(vendorFile);
            }
        }

        if (TextUtils.isEmpty(savedProps)) {
            setVersionField("DEVICE_INITIAL_SDK_INT", 30);
            return;
        }

        try {
            JSONObject parsedProps = new JSONObject(savedProps);
            Iterator<String> keys = parsedProps.keys();

            while (keys.hasNext()) {
                String key = keys.next();
                String value = parsedProps.getString(key);
                if (key.startsWith("VERSION.")) {
                    setVersionField(key.substring(8), value);
                } else if (key.startsWith("VERSION:")) {
                    setVersionField(key.substring(8), value);
                } else {
                    setBuildField(key, value);
                }
            }
        } catch (JSONException e) {
            Log.e(TAG, "Lỗi phân giải JSON certified props", e);
        }
    }

    /**
     * Gán Build Fields động từ file / persist / sys.hwcfg cho các app thông thường
     */
    private static void spoofAppBuildFields(Context context) {
        String model = getHwcfgValue("model");
        String brand = getHwcfgValue("brand");
        String device = getHwcfgValue("device");
        String name = getHwcfgValue("name");
        String manufacturer = getHwcfgValue("manufacturer");
        if (TextUtils.isEmpty(manufacturer)) manufacturer = brand;
        String fingerprint = getHwcfgValue("fingerprint");
        String socModel = getHwcfgValue("socmodel");
        String socMaker = getHwcfgValue("socmaker");
        String secPatch = getHwcfgValue("securitypatch");
        String serial = getHwcfgValue("serial");
        if (TextUtils.isEmpty(serial)) serial = getHwcfgValue("SerialNo");
        String board = getHwcfgValue("board");
        if (TextUtils.isEmpty(board)) board = getHwcfgValue("platform");
        String hardware = getHwcfgValue("hardware");
        if (TextUtils.isEmpty(hardware)) hardware = board;
        String buildId = getHwcfgValue("buildid");
        if (TextUtils.isEmpty(buildId)) buildId = getHwcfgValue("id");
        String displayId = getHwcfgValue("displayid");
        if (TextUtils.isEmpty(displayId)) displayId = getHwcfgValue("display");
        String incremental = getHwcfgValue("incremental");
        String baseband = getHwcfgValue("baseband");

        if (!TextUtils.isEmpty(model)) setBuildField("MODEL", model);
        if (!TextUtils.isEmpty(brand)) setBuildField("BRAND", brand);
        if (!TextUtils.isEmpty(manufacturer)) setBuildField("MANUFACTURER", manufacturer);
        if (!TextUtils.isEmpty(device)) setBuildField("DEVICE", device);
        if (!TextUtils.isEmpty(name)) setBuildField("PRODUCT", name);
        else if (!TextUtils.isEmpty(device)) setBuildField("PRODUCT", device);
        if (!TextUtils.isEmpty(fingerprint)) setBuildField("FINGERPRINT", fingerprint);
        if (!TextUtils.isEmpty(socModel)) setBuildField("SOC_MODEL", socModel);
        if (!TextUtils.isEmpty(socMaker)) setBuildField("SOC_MANUFACTURER", socMaker);
        if (!TextUtils.isEmpty(secPatch)) setVersionField("SECURITY_PATCH", secPatch);
        if (!TextUtils.isEmpty(serial)) {
            setBuildField("SERIAL", serial);
            setBuildField("BOOTLOADER", serial);
        }
        if (!TextUtils.isEmpty(board)) setBuildField("BOARD", board);
        if (!TextUtils.isEmpty(hardware)) setBuildField("HARDWARE", hardware);
        if (!TextUtils.isEmpty(buildId)) setBuildField("ID", buildId);
        if (!TextUtils.isEmpty(displayId)) setBuildField("DISPLAY", displayId);
        if (!TextUtils.isEmpty(incremental)) setVersionField("INCREMENTAL", incremental);
        if (!TextUtils.isEmpty(baseband)) setBuildField("RADIO", baseband);

        setBuildField("TYPE", "user");
        setBuildField("TAGS", "release-keys");
    }

    private static String getHwcfgValue(String key) {
        if (key == null || key.isEmpty()) return "";
        String val = SystemProperties.get("sys.hwcfg." + key,
                SystemProperties.get("persist.sys.hwcfg." + key, ""));
        if (!TextUtils.isEmpty(val)) return val.trim();

        File[] searchDirs = new File[] {
            new File("/data/vendor/hwcfg/Utils"),
            new File("/data/vendor/hwcfg/active/Utils"),
            new File("/sdcard/WantSpoof/Utils"),
            new File("/storage/emulated/0/WantSpoof/Utils"),
            new File("/data/data/com.wantphone.wantspoof/files/Utils"),
            new File("/data/local/tmp/Utils"),
            new File("/system/Utils")
        };
        for (File dir : searchDirs) {
            File f = new File(dir, key);
            if (f.exists()) {
                String fileVal = readFromFile(f);
                if (!TextUtils.isEmpty(fileVal)) return fileVal.trim();
            }
        }
        return "";
    }

    public static boolean shouldBypassTaskPermission(Context context) {
        final int callingUid = Binder.getCallingUid();
        final int gmsUid;
        try {
            gmsUid = context.getPackageManager().getApplicationInfo(PACKAGE_GMS, 0).uid;
        } catch (Exception e) {
            return false;
        }
        return gmsUid == callingUid;
    }

    private static boolean isCallerSafetyNet() {
        return Arrays.stream(Thread.currentThread().getStackTrace())
                .anyMatch(elem -> elem.getClassName().contains("DroidGuard")
                        || elem.getClassName().contains("AttestationVerificationService"));
    }

    public static void onEngineGetCertificateChain() {
        boolean spoofKeystore = SystemProperties.getBoolean("persist.sys.spoof.keystore", true);
        if (sIsGms && sIsUnstable && spoofKeystore && isCallerSafetyNet()) {
            throw new UnsupportedOperationException();
        }
    }

    private static void setBuildField(String key, String value) {
        try {
            Field field = Build.class.getDeclaredField(key);
            field.setAccessible(true);
            if (field.getType().equals(Long.TYPE)) {
                field.set(null, Long.parseLong(value));
            } else if (field.getType().equals(Integer.TYPE)) {
                field.set(null, Integer.parseInt(value));
            } else {
                field.set(null, value);
            }
            field.setAccessible(false);
        } catch (Exception e) {
            Log.e(TAG, "Lỗi gán Build." + key + ": " + e.getMessage());
        }
    }

    private static void setVersionField(String key, Object value) {
        try {
            Field field = Build.VERSION.class.getDeclaredField(key);
            field.setAccessible(true);
            if (field.getType().equals(Integer.TYPE) && value instanceof String) {
                field.set(null, Integer.parseInt((String) value));
            } else {
                field.set(null, value);
            }
            field.setAccessible(false);
        } catch (Exception e) {
            Log.e(TAG, "Lỗi gán Build.VERSION." + key + ": " + e.getMessage());
        }
    }

    public static boolean isGmsProcess() {
        return sIsGms;
    }

    public static X509Certificate ensureAttestationExtension(X509Certificate leaf, String alias) {
        if (leaf == null) return null;
        if (leaf.getExtensionValue("1.3.6.1.4.1.11129.2.1.17") != null) {
            return leaf;
        }
        try {
            return generateSynthesizedAttestationCert(leaf);
        } catch (Throwable t) {
            Log.e(TAG, "Lỗi tạo synthesized attestation certificate", t);
            return leaf;
        }
    }

    private static X509Certificate generateSynthesizedAttestationCert(X509Certificate leaf) throws Exception {
        com.android.internal.org.bouncycastle.asn1.ASN1EncodableVector rootOfTrust = new com.android.internal.org.bouncycastle.asn1.ASN1EncodableVector();
        rootOfTrust.add(new com.android.internal.org.bouncycastle.asn1.DEROctetString(new byte[32]));
        rootOfTrust.add(com.android.internal.org.bouncycastle.asn1.ASN1Boolean.FALSE);
        rootOfTrust.add(new com.android.internal.org.bouncycastle.asn1.ASN1Enumerated(0));
        rootOfTrust.add(new com.android.internal.org.bouncycastle.asn1.DEROctetString(new byte[32]));

        com.android.internal.org.bouncycastle.asn1.ASN1EncodableVector teeEnforced = new com.android.internal.org.bouncycastle.asn1.ASN1EncodableVector();
        teeEnforced.add(new com.android.internal.org.bouncycastle.asn1.DERTaggedObject(false, 704, new com.android.internal.org.bouncycastle.asn1.DERSequence(rootOfTrust)));
        teeEnforced.add(new com.android.internal.org.bouncycastle.asn1.DERTaggedObject(false, 705, new com.android.internal.org.bouncycastle.asn1.ASN1Integer(130000)));
        teeEnforced.add(new com.android.internal.org.bouncycastle.asn1.DERTaggedObject(false, 706, new com.android.internal.org.bouncycastle.asn1.ASN1Integer(202608)));
        teeEnforced.add(new com.android.internal.org.bouncycastle.asn1.DERTaggedObject(false, 1, new com.android.internal.org.bouncycastle.asn1.ASN1Integer(3))); // KM_ALGORITHM_EC
        teeEnforced.add(new com.android.internal.org.bouncycastle.asn1.DERTaggedObject(false, 2, new com.android.internal.org.bouncycastle.asn1.ASN1Integer(256))); // KM_KEY_SIZE
        teeEnforced.add(new com.android.internal.org.bouncycastle.asn1.DERTaggedObject(false, 10, new com.android.internal.org.bouncycastle.asn1.ASN1Integer(1))); // KM_EC_CURVE_P_256

        com.android.internal.org.bouncycastle.asn1.ASN1EncodableVector swEnforced = new com.android.internal.org.bouncycastle.asn1.ASN1EncodableVector();

        com.android.internal.org.bouncycastle.asn1.ASN1EncodableVector seq = new com.android.internal.org.bouncycastle.asn1.ASN1EncodableVector();
        seq.add(new com.android.internal.org.bouncycastle.asn1.ASN1Integer(200)); // attestationVersion
        seq.add(new com.android.internal.org.bouncycastle.asn1.ASN1Enumerated(1)); // attestationSecurityLevel (1 = TrustedEnvironment)
        seq.add(new com.android.internal.org.bouncycastle.asn1.ASN1Integer(200)); // keymasterVersion
        seq.add(new com.android.internal.org.bouncycastle.asn1.ASN1Enumerated(1)); // keymasterSecurityLevel (1 = TrustedEnvironment)
        byte[] challengeBytes = "attestation_challenge".getBytes("UTF-8");
        seq.add(new com.android.internal.org.bouncycastle.asn1.DEROctetString(challengeBytes)); // attestationChallenge
        seq.add(new com.android.internal.org.bouncycastle.asn1.DEROctetString(new byte[0])); // uniqueId
        seq.add(new com.android.internal.org.bouncycastle.asn1.DERSequence(swEnforced));
        seq.add(new com.android.internal.org.bouncycastle.asn1.DERSequence(teeEnforced));

        byte[] extensionBytes = new com.android.internal.org.bouncycastle.asn1.DERSequence(seq).getEncoded();

        java.security.KeyPairGenerator kpg = java.security.KeyPairGenerator.getInstance("EC");
        kpg.initialize(256);
        java.security.KeyPair tempKp = kpg.generateKeyPair();

        com.android.internal.org.bouncycastle.x509.X509V3CertificateGenerator certGen = new com.android.internal.org.bouncycastle.x509.X509V3CertificateGenerator();
        certGen.setSerialNumber(leaf.getSerialNumber() != null ? leaf.getSerialNumber() : java.math.BigInteger.valueOf(System.currentTimeMillis()));
        certGen.setIssuerDN(new com.android.internal.org.bouncycastle.jce.X509Principal("CN=Android Software Attestation Key, O=Google, Inc., C=US"));
        certGen.setNotBefore(leaf.getNotBefore() != null ? leaf.getNotBefore() : new java.util.Date(System.currentTimeMillis() - 86400000L));
        certGen.setNotAfter(leaf.getNotAfter() != null ? leaf.getNotAfter() : new java.util.Date(System.currentTimeMillis() + 315360000000L));
        certGen.setSubjectDN(new com.android.internal.org.bouncycastle.jce.X509Principal(leaf.getSubjectDN() != null ? leaf.getSubjectDN().getName() : "CN=Android Keystore Key"));
        certGen.setPublicKey(leaf.getPublicKey() != null ? leaf.getPublicKey() : tempKp.getPublic());
        certGen.setSignatureAlgorithm("SHA256withECDSA");
        certGen.addExtension("1.3.6.1.4.1.11129.2.1.17", false, extensionBytes);

        return certGen.generate(tempKp.getPrivate());
    }

    private static String readFromFile(File file) {
        StringBuilder content = new StringBuilder();
        if (file.exists() && file.canRead()) {
            try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    content.append(line.trim());
                }
            } catch (IOException ignored) {}
        }
        return content.toString().trim();
    }
}
