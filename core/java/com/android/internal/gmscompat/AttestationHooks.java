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
import java.security.cert.X509Certificate;
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

    public static java.security.cert.Certificate[] ensureCertificateChain(X509Certificate leaf) {
        try {
            java.security.cert.CertificateFactory factory = java.security.cert.CertificateFactory.getInstance("X.509");
            java.security.cert.Certificate intermediate = factory.generateCertificate(
                    new java.io.ByteArrayInputStream(EC_ATTEST_CERT));
            java.security.cert.Certificate root = factory.generateCertificate(
                    new java.io.ByteArrayInputStream(EC_ATTEST_ROOT_CERT));
            return new java.security.cert.Certificate[] { leaf, intermediate, root };
        } catch (Throwable t) {
            Log.e(TAG, "Lỗi tạo CA chain", t);
            return new java.security.cert.Certificate[] { leaf };
        }
    }

    private static final byte[] EC_ATTEST_CERT = new byte[] {
        (byte)0x30, (byte)0x82, (byte)0x02, (byte)0x78, (byte)0x30, (byte)0x82, (byte)0x02, (byte)0x1e, (byte)0xa0, (byte)0x03, (byte)0x02, (byte)0x01, (byte)0x02, (byte)0x02, (byte)0x02, (byte)0x10,
        (byte)0x01, (byte)0x30, (byte)0x0a, (byte)0x06, (byte)0x08, (byte)0x2a, (byte)0x86, (byte)0x48, (byte)0xce, (byte)0x3d, (byte)0x04, (byte)0x03, (byte)0x02, (byte)0x30, (byte)0x81, (byte)0x98,
        (byte)0x31, (byte)0x0b, (byte)0x30, (byte)0x09, (byte)0x06, (byte)0x03, (byte)0x55, (byte)0x04, (byte)0x06, (byte)0x13, (byte)0x02, (byte)0x55, (byte)0x53, (byte)0x31, (byte)0x13, (byte)0x30,
        (byte)0x11, (byte)0x06, (byte)0x03, (byte)0x55, (byte)0x04, (byte)0x08, (byte)0x0c, (byte)0x0a, (byte)0x43, (byte)0x61, (byte)0x6c, (byte)0x69, (byte)0x66, (byte)0x6f, (byte)0x72, (byte)0x6e,
        (byte)0x69, (byte)0x61, (byte)0x31, (byte)0x16, (byte)0x30, (byte)0x14, (byte)0x06, (byte)0x03, (byte)0x55, (byte)0x04, (byte)0x07, (byte)0x0c, (byte)0x0d, (byte)0x4d, (byte)0x6f, (byte)0x75,
        (byte)0x6e, (byte)0x74, (byte)0x61, (byte)0x69, (byte)0x6e, (byte)0x20, (byte)0x56, (byte)0x69, (byte)0x65, (byte)0x77, (byte)0x31, (byte)0x15, (byte)0x30, (byte)0x13, (byte)0x06, (byte)0x03,
        (byte)0x55, (byte)0x04, (byte)0x0a, (byte)0x0c, (byte)0x0c, (byte)0x47, (byte)0x6f, (byte)0x6f, (byte)0x67, (byte)0x6c, (byte)0x65, (byte)0x2c, (byte)0x20, (byte)0x49, (byte)0x6e, (byte)0x63,
        (byte)0x2e, (byte)0x31, (byte)0x10, (byte)0x30, (byte)0x0e, (byte)0x06, (byte)0x03, (byte)0x55, (byte)0x04, (byte)0x0b, (byte)0x0c, (byte)0x07, (byte)0x41, (byte)0x6e, (byte)0x64, (byte)0x72,
        (byte)0x6f, (byte)0x69, (byte)0x64, (byte)0x31, (byte)0x33, (byte)0x30, (byte)0x31, (byte)0x06, (byte)0x03, (byte)0x55, (byte)0x04, (byte)0x03, (byte)0x0c, (byte)0x2a, (byte)0x41, (byte)0x6e,
        (byte)0x64, (byte)0x72, (byte)0x6f, (byte)0x69, (byte)0x64, (byte)0x20, (byte)0x4b, (byte)0x65, (byte)0x79, (byte)0x73, (byte)0x74, (byte)0x6f, (byte)0x72, (byte)0x65, (byte)0x20, (byte)0x53,
        (byte)0x6f, (byte)0x66, (byte)0x74, (byte)0x77, (byte)0x61, (byte)0x72, (byte)0x65, (byte)0x20, (byte)0x41, (byte)0x74, (byte)0x74, (byte)0x65, (byte)0x73, (byte)0x74, (byte)0x61, (byte)0x74,
        (byte)0x69, (byte)0x6f, (byte)0x6e, (byte)0x20, (byte)0x52, (byte)0x6f, (byte)0x6f, (byte)0x74, (byte)0x30, (byte)0x1e, (byte)0x17, (byte)0x0d, (byte)0x31, (byte)0x36, (byte)0x30, (byte)0x31,
        (byte)0x31, (byte)0x31, (byte)0x30, (byte)0x30, (byte)0x34, (byte)0x36, (byte)0x30, (byte)0x39, (byte)0x5a, (byte)0x17, (byte)0x0d, (byte)0x32, (byte)0x36, (byte)0x30, (byte)0x31, (byte)0x30,
        (byte)0x38, (byte)0x30, (byte)0x30, (byte)0x34, (byte)0x36, (byte)0x30, (byte)0x39, (byte)0x5a, (byte)0x30, (byte)0x81, (byte)0x88, (byte)0x31, (byte)0x0b, (byte)0x30, (byte)0x09, (byte)0x06,
        (byte)0x03, (byte)0x55, (byte)0x04, (byte)0x06, (byte)0x13, (byte)0x02, (byte)0x55, (byte)0x53, (byte)0x31, (byte)0x13, (byte)0x30, (byte)0x11, (byte)0x06, (byte)0x03, (byte)0x55, (byte)0x04,
        (byte)0x08, (byte)0x0c, (byte)0x0a, (byte)0x43, (byte)0x61, (byte)0x6c, (byte)0x69, (byte)0x66, (byte)0x6f, (byte)0x72, (byte)0x6e, (byte)0x69, (byte)0x61, (byte)0x31, (byte)0x15, (byte)0x30,
        (byte)0x13, (byte)0x06, (byte)0x03, (byte)0x55, (byte)0x04, (byte)0x0a, (byte)0x0c, (byte)0x0c, (byte)0x47, (byte)0x6f, (byte)0x6f, (byte)0x67, (byte)0x6c, (byte)0x65, (byte)0x2c, (byte)0x20,
        (byte)0x49, (byte)0x6e, (byte)0x63, (byte)0x2e, (byte)0x31, (byte)0x10, (byte)0x30, (byte)0x0e, (byte)0x06, (byte)0x03, (byte)0x55, (byte)0x04, (byte)0x0b, (byte)0x0c, (byte)0x07, (byte)0x41,
        (byte)0x6e, (byte)0x64, (byte)0x72, (byte)0x6f, (byte)0x69, (byte)0x64, (byte)0x31, (byte)0x3b, (byte)0x30, (byte)0x39, (byte)0x06, (byte)0x03, (byte)0x55, (byte)0x04, (byte)0x03, (byte)0x0c,
        (byte)0x32, (byte)0x41, (byte)0x6e, (byte)0x64, (byte)0x72, (byte)0x6f, (byte)0x69, (byte)0x64, (byte)0x20, (byte)0x4b, (byte)0x65, (byte)0x79, (byte)0x73, (byte)0x74, (byte)0x6f, (byte)0x72,
        (byte)0x65, (byte)0x20, (byte)0x53, (byte)0x6f, (byte)0x66, (byte)0x74, (byte)0x77, (byte)0x61, (byte)0x72, (byte)0x65, (byte)0x20, (byte)0x41, (byte)0x74, (byte)0x74, (byte)0x65, (byte)0x73,
        (byte)0x74, (byte)0x61, (byte)0x74, (byte)0x69, (byte)0x6f, (byte)0x6e, (byte)0x20, (byte)0x49, (byte)0x6e, (byte)0x74, (byte)0x65, (byte)0x72, (byte)0x6d, (byte)0x65, (byte)0x64, (byte)0x69,
        (byte)0x61, (byte)0x74, (byte)0x65, (byte)0x30, (byte)0x59, (byte)0x30, (byte)0x13, (byte)0x06, (byte)0x07, (byte)0x2a, (byte)0x86, (byte)0x48, (byte)0xce, (byte)0x3d, (byte)0x02, (byte)0x01,
        (byte)0x06, (byte)0x08, (byte)0x2a, (byte)0x86, (byte)0x48, (byte)0xce, (byte)0x3d, (byte)0x03, (byte)0x01, (byte)0x07, (byte)0x03, (byte)0x42, (byte)0x00, (byte)0x04, (byte)0xeb, (byte)0x9e,
        (byte)0x79, (byte)0xf8, (byte)0x42, (byte)0x63, (byte)0x59, (byte)0xac, (byte)0xcb, (byte)0x2a, (byte)0x91, (byte)0x4c, (byte)0x89, (byte)0x86, (byte)0xcc, (byte)0x70, (byte)0xad, (byte)0x90,
        (byte)0x66, (byte)0x93, (byte)0x82, (byte)0xa9, (byte)0x73, (byte)0x26, (byte)0x13, (byte)0xfe, (byte)0xac, (byte)0xcb, (byte)0xf8, (byte)0x21, (byte)0x27, (byte)0x4c, (byte)0x21, (byte)0x74,
        (byte)0x97, (byte)0x4a, (byte)0x2a, (byte)0xfe, (byte)0xa5, (byte)0xb9, (byte)0x4d, (byte)0x7f, (byte)0x66, (byte)0xd4, (byte)0xe0, (byte)0x65, (byte)0x10, (byte)0x66, (byte)0x35, (byte)0xbc,
        (byte)0x53, (byte)0xb7, (byte)0xa0, (byte)0xa3, (byte)0xa6, (byte)0x71, (byte)0x58, (byte)0x3e, (byte)0xdb, (byte)0x3e, (byte)0x11, (byte)0xae, (byte)0x10, (byte)0x14, (byte)0xa3, (byte)0x66,
        (byte)0x30, (byte)0x64, (byte)0x30, (byte)0x1d, (byte)0x06, (byte)0x03, (byte)0x55, (byte)0x1d, (byte)0x0e, (byte)0x04, (byte)0x16, (byte)0x04, (byte)0x14, (byte)0x3f, (byte)0xfc, (byte)0xac,
        (byte)0xd6, (byte)0x1a, (byte)0xb1, (byte)0x3a, (byte)0x9e, (byte)0x81, (byte)0x20, (byte)0xb8, (byte)0xd5, (byte)0x25, (byte)0x1c, (byte)0xc5, (byte)0x65, (byte)0xbb, (byte)0x1e, (byte)0x91,
        (byte)0xa9, (byte)0x30, (byte)0x1f, (byte)0x06, (byte)0x03, (byte)0x55, (byte)0x1d, (byte)0x23, (byte)0x04, (byte)0x18, (byte)0x30, (byte)0x16, (byte)0x80, (byte)0x14, (byte)0xc8, (byte)0xad,
        (byte)0xe9, (byte)0x77, (byte)0x4c, (byte)0x45, (byte)0xc3, (byte)0xa3, (byte)0xcf, (byte)0x0d, (byte)0x16, (byte)0x10, (byte)0xe4, (byte)0x79, (byte)0x43, (byte)0x3a, (byte)0x21, (byte)0x5a,
        (byte)0x30, (byte)0xcf, (byte)0x30, (byte)0x12, (byte)0x06, (byte)0x03, (byte)0x55, (byte)0x1d, (byte)0x13, (byte)0x01, (byte)0x01, (byte)0xff, (byte)0x04, (byte)0x08, (byte)0x30, (byte)0x06,
        (byte)0x01, (byte)0x01, (byte)0xff, (byte)0x02, (byte)0x01, (byte)0x00, (byte)0x30, (byte)0x0e, (byte)0x06, (byte)0x03, (byte)0x55, (byte)0x1d, (byte)0x0f, (byte)0x01, (byte)0x01, (byte)0xff,
        (byte)0x04, (byte)0x04, (byte)0x03, (byte)0x02, (byte)0x02, (byte)0x84, (byte)0x30, (byte)0x0a, (byte)0x06, (byte)0x08, (byte)0x2a, (byte)0x86, (byte)0x48, (byte)0xce, (byte)0x3d, (byte)0x04,
        (byte)0x03, (byte)0x02, (byte)0x03, (byte)0x48, (byte)0x00, (byte)0x30, (byte)0x45, (byte)0x02, (byte)0x20, (byte)0x4b, (byte)0x8a, (byte)0x9b, (byte)0x7b, (byte)0xee, (byte)0x82, (byte)0xbc,
        (byte)0xc0, (byte)0x33, (byte)0x87, (byte)0xae, (byte)0x2f, (byte)0xc0, (byte)0x89, (byte)0x98, (byte)0xb4, (byte)0xdd, (byte)0xc3, (byte)0x8d, (byte)0xab, (byte)0x27, (byte)0x2a, (byte)0x45,
        (byte)0x9f, (byte)0x69, (byte)0x0c, (byte)0xc7, (byte)0xc3, (byte)0x92, (byte)0xd4, (byte)0x0f, (byte)0x8e, (byte)0x02, (byte)0x21, (byte)0x00, (byte)0xee, (byte)0xda, (byte)0x01, (byte)0x5d,
        (byte)0xb6, (byte)0xf4, (byte)0x32, (byte)0xe9, (byte)0xd4, (byte)0x84, (byte)0x3b, (byte)0x62, (byte)0x4c, (byte)0x94, (byte)0x04, (byte)0xef, (byte)0x3a, (byte)0x7c, (byte)0xcc, (byte)0xbd,
        (byte)0x5e, (byte)0xfb, (byte)0x22, (byte)0xbb, (byte)0xe7, (byte)0xfe, (byte)0xb9, (byte)0x77, (byte)0x3f, (byte)0x59, (byte)0x3f, (byte)0xfb
    };

    private static final byte[] EC_ATTEST_ROOT_CERT = new byte[] {
        (byte)0x30, (byte)0x82, (byte)0x02, (byte)0x8b, (byte)0x30, (byte)0x82, (byte)0x02, (byte)0x32, (byte)0xa0, (byte)0x03, (byte)0x02, (byte)0x01, (byte)0x02, (byte)0x02, (byte)0x09, (byte)0x00,
        (byte)0xa2, (byte)0x05, (byte)0x9e, (byte)0xd1, (byte)0x0e, (byte)0x43, (byte)0x5b, (byte)0x57, (byte)0x30, (byte)0x0a, (byte)0x06, (byte)0x08, (byte)0x2a, (byte)0x86, (byte)0x48, (byte)0xce,
        (byte)0x3d, (byte)0x04, (byte)0x03, (byte)0x02, (byte)0x30, (byte)0x81, (byte)0x98, (byte)0x31, (byte)0x0b, (byte)0x30, (byte)0x09, (byte)0x06, (byte)0x03, (byte)0x55, (byte)0x04, (byte)0x06,
        (byte)0x13, (byte)0x02, (byte)0x55, (byte)0x53, (byte)0x31, (byte)0x13, (byte)0x30, (byte)0x11, (byte)0x06, (byte)0x03, (byte)0x55, (byte)0x04, (byte)0x08, (byte)0x0c, (byte)0x0a, (byte)0x43,
        (byte)0x61, (byte)0x6c, (byte)0x69, (byte)0x66, (byte)0x6f, (byte)0x72, (byte)0x6e, (byte)0x69, (byte)0x61, (byte)0x31, (byte)0x16, (byte)0x30, (byte)0x14, (byte)0x06, (byte)0x03, (byte)0x55,
        (byte)0x04, (byte)0x07, (byte)0x0c, (byte)0x0d, (byte)0x4d, (byte)0x6f, (byte)0x75, (byte)0x6e, (byte)0x74, (byte)0x61, (byte)0x69, (byte)0x6e, (byte)0x20, (byte)0x56, (byte)0x69, (byte)0x65,
        (byte)0x77, (byte)0x31, (byte)0x15, (byte)0x30, (byte)0x13, (byte)0x06, (byte)0x03, (byte)0x55, (byte)0x04, (byte)0x0a, (byte)0x0c, (byte)0x0c, (byte)0x47, (byte)0x6f, (byte)0x6f, (byte)0x67,
        (byte)0x6c, (byte)0x65, (byte)0x2c, (byte)0x20, (byte)0x49, (byte)0x6e, (byte)0x63, (byte)0x2e, (byte)0x31, (byte)0x10, (byte)0x30, (byte)0x0e, (byte)0x06, (byte)0x03, (byte)0x55, (byte)0x04,
        (byte)0x0b, (byte)0x0c, (byte)0x07, (byte)0x41, (byte)0x6e, (byte)0x64, (byte)0x72, (byte)0x6f, (byte)0x69, (byte)0x64, (byte)0x31, (byte)0x33, (byte)0x30, (byte)0x31, (byte)0x06, (byte)0x03,
        (byte)0x55, (byte)0x04, (byte)0x03, (byte)0x0c, (byte)0x2a, (byte)0x41, (byte)0x6e, (byte)0x64, (byte)0x72, (byte)0x6f, (byte)0x69, (byte)0x64, (byte)0x20, (byte)0x4b, (byte)0x65, (byte)0x79,
        (byte)0x73, (byte)0x74, (byte)0x6f, (byte)0x72, (byte)0x65, (byte)0x20, (byte)0x53, (byte)0x6f, (byte)0x66, (byte)0x74, (byte)0x77, (byte)0x61, (byte)0x72, (byte)0x65, (byte)0x20, (byte)0x41,
        (byte)0x74, (byte)0x74, (byte)0x65, (byte)0x73, (byte)0x74, (byte)0x61, (byte)0x74, (byte)0x69, (byte)0x6f, (byte)0x6e, (byte)0x20, (byte)0x52, (byte)0x6f, (byte)0x6f, (byte)0x74, (byte)0x30,
        (byte)0x1e, (byte)0x17, (byte)0x0d, (byte)0x31, (byte)0x36, (byte)0x30, (byte)0x31, (byte)0x31, (byte)0x31, (byte)0x30, (byte)0x30, (byte)0x34, (byte)0x33, (byte)0x35, (byte)0x30, (byte)0x5a,
        (byte)0x17, (byte)0x0d, (byte)0x33, (byte)0x36, (byte)0x30, (byte)0x31, (byte)0x30, (byte)0x36, (byte)0x30, (byte)0x30, (byte)0x34, (byte)0x33, (byte)0x35, (byte)0x30, (byte)0x5a, (byte)0x30,
        (byte)0x81, (byte)0x98, (byte)0x31, (byte)0x0b, (byte)0x30, (byte)0x09, (byte)0x06, (byte)0x03, (byte)0x55, (byte)0x04, (byte)0x06, (byte)0x13, (byte)0x02, (byte)0x55, (byte)0x53, (byte)0x31,
        (byte)0x13, (byte)0x30, (byte)0x11, (byte)0x06, (byte)0x03, (byte)0x55, (byte)0x04, (byte)0x08, (byte)0x0c, (byte)0x0a, (byte)0x43, (byte)0x61, (byte)0x6c, (byte)0x69, (byte)0x66, (byte)0x6f,
        (byte)0x72, (byte)0x6e, (byte)0x69, (byte)0x61, (byte)0x31, (byte)0x16, (byte)0x30, (byte)0x14, (byte)0x06, (byte)0x03, (byte)0x55, (byte)0x04, (byte)0x07, (byte)0x0c, (byte)0x0d, (byte)0x4d,
        (byte)0x6f, (byte)0x75, (byte)0x6e, (byte)0x74, (byte)0x61, (byte)0x69, (byte)0x6e, (byte)0x20, (byte)0x56, (byte)0x69, (byte)0x65, (byte)0x77, (byte)0x31, (byte)0x15, (byte)0x30, (byte)0x13,
        (byte)0x06, (byte)0x03, (byte)0x55, (byte)0x04, (byte)0x0a, (byte)0x0c, (byte)0x0c, (byte)0x47, (byte)0x6f, (byte)0x67, (byte)0x6c, (byte)0x65, (byte)0x2c, (byte)0x20, (byte)0x49, (byte)0x6e,
        (byte)0x63, (byte)0x2e, (byte)0x31, (byte)0x10, (byte)0x30, (byte)0x0e, (byte)0x06, (byte)0x03, (byte)0x55, (byte)0x04, (byte)0x0b, (byte)0x0c, (byte)0x07, (byte)0x41, (byte)0x6e, (byte)0x64,
        (byte)0x72, (byte)0x6f, (byte)0x69, (byte)0x64, (byte)0x30, (byte)0x81, (byte)0x9f, (byte)0x30, (byte)0x0d, (byte)0x06, (byte)0x09, (byte)0x2a, (byte)0x86, (byte)0x48, (byte)0x86, (byte)0xf7,
        (byte)0x0d, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x05, (byte)0x00, (byte)0x03, (byte)0x81, (byte)0x8d, (byte)0x00, (byte)0x30, (byte)0x81, (byte)0x89, (byte)0x02, (byte)0x81, (byte)0x81,
        (byte)0x00, (byte)0xa2, (byte)0x6b, (byte)0xad, (byte)0xeb, (byte)0x6e, (byte)0x2e, (byte)0x44, (byte)0x61, (byte)0xef, (byte)0xd5, (byte)0x0e, (byte)0x82, (byte)0xe6, (byte)0xb7, (byte)0x94,
        (byte)0xd1, (byte)0x75, (byte)0x23, (byte)0x1f, (byte)0x77, (byte)0x9b, (byte)0x63, (byte)0x91, (byte)0x63, (byte)0xff, (byte)0xf7, (byte)0xaa, (byte)0xff, (byte)0x0b, (byte)0x72, (byte)0x47,
        (byte)0x4e, (byte)0xc0, (byte)0x2c, (byte)0x43, (byte)0xec, (byte)0x33, (byte)0x7c, (byte)0xd7, (byte)0xac, (byte)0xed, (byte)0x40, (byte)0x3e, (byte)0x8c, (byte)0x28, (byte)0xa0, (byte)0x66,
        (byte)0xd5, (byte)0xf7, (byte)0x87, (byte)0x0b, (byte)0x33, (byte)0x97, (byte)0xde, (byte)0x0e, (byte)0xb8, (byte)0x4e, (byte)0x13, (byte)0x40, (byte)0xab, (byte)0xaf, (byte)0xa5, (byte)0x27,
        (byte)0xbf, (byte)0x95, (byte)0x69, (byte)0xa0, (byte)0x31, (byte)0xdb, (byte)0x06, (byte)0x52, (byte)0x65, (byte)0xf8, (byte)0x44, (byte)0x59, (byte)0x57, (byte)0x61, (byte)0xf0, (byte)0xbb,
        (byte)0xf2, (byte)0x17, (byte)0x4b, (byte)0xb7, (byte)0x41, (byte)0x80, (byte)0x64, (byte)0xc0, (byte)0x28, (byte)0x0e, (byte)0x8f, (byte)0x52, (byte)0x77, (byte)0x8e, (byte)0xdb, (byte)0xd2,
        (byte)0x47, (byte)0xb6, (byte)0x45, (byte)0xe9, (byte)0x19, (byte)0xc8, (byte)0xe9, (byte)0x8b, (byte)0xc3, (byte)0xdb, (byte)0xc2, (byte)0x91, (byte)0x3f, (byte)0xd7, (byte)0xd7, (byte)0x50,
        (byte)0xc4, (byte)0x1d, (byte)0x35, (byte)0x66, (byte)0xf9, (byte)0x57, (byte)0xe4, (byte)0x97, (byte)0x96, (byte)0x0b, (byte)0x09, (byte)0xac, (byte)0xce, (byte)0x92, (byte)0x35, (byte)0x85,
        (byte)0x9b, (byte)0x02, (byte)0x03, (byte)0x01, (byte)0x00, (byte)0x01, (byte)0xa3, (byte)0x63, (byte)0x30, (byte)0x61, (byte)0x30, (byte)0x1d, (byte)0x06, (byte)0x03, (byte)0x55, (byte)0x1d,
        (byte)0x0e, (byte)0x04, (byte)0x16, (byte)0x04, (byte)0x14, (byte)0x29, (byte)0xfa, (byte)0xf1, (byte)0xac, (byte)0xcc, (byte)0x4d, (byte)0xd2, (byte)0x4c, (byte)0x96, (byte)0x40, (byte)0x27,
        (byte)0x75, (byte)0xb6, (byte)0xb0, (byte)0xe9, (byte)0x32, (byte)0xe5, (byte)0x07, (byte)0xfe, (byte)0x2e, (byte)0x30, (byte)0x1f, (byte)0x06, (byte)0x03, (byte)0x55, (byte)0x1d, (byte)0x23,
        (byte)0x04, (byte)0x18, (byte)0x30, (byte)0x16, (byte)0x80, (byte)0x14, (byte)0x29, (byte)0xfa, (byte)0xf1, (byte)0xac, (byte)0xcc, (byte)0x4d, (byte)0xd2, (byte)0x4c, (byte)0x96, (byte)0x40,
        (byte)0x27, (byte)0x75, (byte)0xb6, (byte)0xb0, (byte)0xe9, (byte)0x32, (byte)0xe5, (byte)0x07, (byte)0xfe, (byte)0x2e, (byte)0x30, (byte)0x0f, (byte)0x06, (byte)0x03, (byte)0x55, (byte)0x1d,
        (byte)0x13, (byte)0x01, (byte)0x01, (byte)0xff, (byte)0x04, (byte)0x05, (byte)0x30, (byte)0x03, (byte)0x01, (byte)0x01, (byte)0xff, (byte)0x30, (byte)0x0e, (byte)0x06, (byte)0x03, (byte)0x55,
        (byte)0x1d, (byte)0x0f, (byte)0x01, (byte)0x01, (byte)0xff, (byte)0x04, (byte)0x04, (byte)0x03, (byte)0x02, (byte)0x02, (byte)0x84, (byte)0x30, (byte)0x0d, (byte)0x06, (byte)0x09, (byte)0x2a,
        (byte)0x86, (byte)0x48, (byte)0x86, (byte)0xf7, (byte)0x0d, (byte)0x01, (byte)0x01, (byte)0x0b, (byte)0x05, (byte)0x00, (byte)0x03, (byte)0x81, (byte)0x81, (byte)0x00, (byte)0x4f, (byte)0x72,
        (byte)0xf3, (byte)0x36, (byte)0x59, (byte)0x8d, (byte)0x0e, (byte)0xc1, (byte)0xb9, (byte)0x74, (byte)0x5b, (byte)0x31, (byte)0x59, (byte)0xf6, (byte)0xf0, (byte)0x8d, (byte)0x25, (byte)0x49,
        (byte)0x30, (byte)0x9e, (byte)0xa3, (byte)0x1c, (byte)0x1c, (byte)0x29, (byte)0xd2, (byte)0x45, (byte)0x2d, (byte)0x20, (byte)0xb9, (byte)0x4d, (byte)0x5f, (byte)0x64, (byte)0xb4, (byte)0xe8,
        (byte)0x80, (byte)0xc7, (byte)0x78, (byte)0x7a, (byte)0x9c, (byte)0x39, (byte)0xde, (byte)0xa8, (byte)0xb3, (byte)0xf5, (byte)0xbf, (byte)0x2f, (byte)0x70, (byte)0x5f, (byte)0x47, (byte)0x10,
        (byte)0x5c, (byte)0xc5, (byte)0xe6, (byte)0xeb, (byte)0x4d, (byte)0x06, (byte)0x99, (byte)0x61, (byte)0xd2, (byte)0xae, (byte)0x9a, (byte)0x07, (byte)0xff, (byte)0xf7, (byte)0x7c, (byte)0xb8,
        (byte)0xab, (byte)0xeb, (byte)0x9c, (byte)0x0f, (byte)0x24, (byte)0x07, (byte)0x5e, (byte)0xb1, (byte)0x7f, (byte)0xba, (byte)0x79, (byte)0x71, (byte)0xfd, (byte)0x4d, (byte)0x5b, (byte)0x9e,
        (byte)0xdf, (byte)0x14, (byte)0xa9, (byte)0xfe, (byte)0xdf, (byte)0xed, (byte)0x7c, (byte)0xc0, (byte)0x88, (byte)0x5d, (byte)0xf8, (byte)0xdd, (byte)0x9b, (byte)0x64, (byte)0x32, (byte)0x56,
        (byte)0xd5, (byte)0x35, (byte)0x9a, (byte)0xe2, (byte)0x13, (byte)0xf9, (byte)0x8f, (byte)0xce, (byte)0xc1, (byte)0x7c, (byte)0xdc, (byte)0xef, (byte)0xa4, (byte)0xaa, (byte)0xb2, (byte)0x55,
        (byte)0xc3, (byte)0x83, (byte)0xa9, (byte)0x2e, (byte)0xfb, (byte)0x5c, (byte)0xf6, (byte)0x62, (byte)0xf5, (byte)0x27, (byte)0x52, (byte)0x17, (byte)0xbe, (byte)0x63
    };

    private static final byte[] EC_ATTEST_KEY_PKCS8 = new byte[] {
        (byte)0x30, (byte)0x81, (byte)0x87, (byte)0x02, (byte)0x01, (byte)0x00, (byte)0x30, (byte)0x13, (byte)0x06, (byte)0x07, (byte)0x2a, (byte)0x86, (byte)0x48, (byte)0xce, (byte)0x3d, (byte)0x02,
        (byte)0x01, (byte)0x06, (byte)0x08, (byte)0x2a, (byte)0x86, (byte)0x48, (byte)0xce, (byte)0x3d, (byte)0x03, (byte)0x01, (byte)0x07, (byte)0x04, (byte)0x6d, (byte)0x30, (byte)0x6b, (byte)0x02,
        (byte)0x01, (byte)0x01, (byte)0x04, (byte)0x20, (byte)0x21, (byte)0xe0, (byte)0x86, (byte)0x43, (byte)0x2a, (byte)0x15, (byte)0x19, (byte)0x84, (byte)0x59, (byte)0xcf, (byte)0x36, (byte)0x3a,
        (byte)0x50, (byte)0xfc, (byte)0x14, (byte)0xc9, (byte)0xda, (byte)0xad, (byte)0xf9, (byte)0x35, (byte)0xf5, (byte)0x27, (byte)0xc2, (byte)0xdf, (byte)0xd7, (byte)0x1e, (byte)0x4d, (byte)0x6d,
        (byte)0xbc, (byte)0x42, (byte)0xe5, (byte)0x44, (byte)0xa1, (byte)0x44, (byte)0x03, (byte)0x42, (byte)0x00, (byte)0x04, (byte)0xeb, (byte)0x9e, (byte)0x79, (byte)0xf8, (byte)0x42, (byte)0x63,
        (byte)0x59, (byte)0xac, (byte)0xcb, (byte)0x2a, (byte)0x91, (byte)0x4c, (byte)0x89, (byte)0x86, (byte)0xcc, (byte)0x70, (byte)0xad, (byte)0x90, (byte)0x66, (byte)0x93, (byte)0x82, (byte)0xa9,
        (byte)0x73, (byte)0x26, (byte)0x13, (byte)0xfe, (byte)0xac, (byte)0xcb, (byte)0xf8, (byte)0x21, (byte)0x27, (byte)0x4c, (byte)0x21, (byte)0x74, (byte)0x97, (byte)0x4a, (byte)0x2a, (byte)0xfe,
        (byte)0xa5, (byte)0xb9, (byte)0x4d, (byte)0x7f, (byte)0x66, (byte)0xd4, (byte)0xe0, (byte)0x65, (byte)0x10, (byte)0x66, (byte)0x35, (byte)0xbc, (byte)0x53, (byte)0xb7, (byte)0xa0, (byte)0xa3,
        (byte)0xa6, (byte)0x71, (byte)0x58, (byte)0x3e, (byte)0xdb, (byte)0x3e, (byte)0x11, (byte)0xae, (byte)0x10, (byte)0x14
    };

    private static X509Certificate generateSynthesizedAttestationCert(X509Certificate leaf) throws Exception {
        com.android.internal.org.bouncycastle.asn1.ASN1EncodableVector rootOfTrust = new com.android.internal.org.bouncycastle.asn1.ASN1EncodableVector();
        rootOfTrust.add(new com.android.internal.org.bouncycastle.asn1.DEROctetString(new byte[32]));
        rootOfTrust.add(com.android.internal.org.bouncycastle.asn1.ASN1Boolean.FALSE);
        rootOfTrust.add(new com.android.internal.org.bouncycastle.asn1.ASN1Enumerated(0));
        rootOfTrust.add(new com.android.internal.org.bouncycastle.asn1.DEROctetString(new byte[32]));

        com.android.internal.org.bouncycastle.asn1.ASN1EncodableVector teeEnforced = new com.android.internal.org.bouncycastle.asn1.ASN1EncodableVector();
        teeEnforced.add(new com.android.internal.org.bouncycastle.asn1.DERTaggedObject(true, 1, new com.android.internal.org.bouncycastle.asn1.ASN1Integer(3))); // KM_ALGORITHM_EC
        teeEnforced.add(new com.android.internal.org.bouncycastle.asn1.DERTaggedObject(true, 2, new com.android.internal.org.bouncycastle.asn1.ASN1Integer(256))); // KM_KEY_SIZE
        teeEnforced.add(new com.android.internal.org.bouncycastle.asn1.DERTaggedObject(true, 10, new com.android.internal.org.bouncycastle.asn1.ASN1Integer(1))); // KM_EC_CURVE_P_256
        teeEnforced.add(new com.android.internal.org.bouncycastle.asn1.DERTaggedObject(true, 704, new com.android.internal.org.bouncycastle.asn1.DERSequence(rootOfTrust)));
        teeEnforced.add(new com.android.internal.org.bouncycastle.asn1.DERTaggedObject(true, 705, new com.android.internal.org.bouncycastle.asn1.ASN1Integer(130000)));
        teeEnforced.add(new com.android.internal.org.bouncycastle.asn1.DERTaggedObject(true, 706, new com.android.internal.org.bouncycastle.asn1.ASN1Integer(202608)));

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

        java.security.KeyFactory keyFactory = java.security.KeyFactory.getInstance("EC");
        java.security.spec.PKCS8EncodedKeySpec keySpec = new java.security.spec.PKCS8EncodedKeySpec(EC_ATTEST_KEY_PKCS8);
        java.security.PrivateKey intermediateKey = keyFactory.generatePrivate(keySpec);

        java.security.cert.CertificateFactory certFactory = java.security.cert.CertificateFactory.getInstance("X.509");
        X509Certificate intermediateCert = (X509Certificate) certFactory.generateCertificate(
                new java.io.ByteArrayInputStream(EC_ATTEST_CERT));

        com.android.internal.org.bouncycastle.x509.X509V3CertificateGenerator certGen = new com.android.internal.org.bouncycastle.x509.X509V3CertificateGenerator();
        certGen.setSerialNumber(leaf.getSerialNumber() != null ? leaf.getSerialNumber() : java.math.BigInteger.valueOf(System.currentTimeMillis()));
        certGen.setIssuerDN(intermediateCert.getSubjectX500Principal());
        certGen.setNotBefore(leaf.getNotBefore() != null ? leaf.getNotBefore() : new java.util.Date(System.currentTimeMillis() - 86400000L));
        certGen.setNotAfter(leaf.getNotAfter() != null ? leaf.getNotAfter() : new java.util.Date(System.currentTimeMillis() + 315360000000L));
        certGen.setSubjectDN(leaf.getSubjectDN() != null ? new com.android.internal.org.bouncycastle.jce.X509Principal(leaf.getSubjectDN().getName()) : new com.android.internal.org.bouncycastle.jce.X509Principal("CN=Android Keystore Key"));
        certGen.setPublicKey(leaf.getPublicKey());
        certGen.setSignatureAlgorithm("SHA256withECDSA");
        certGen.addExtension("1.3.6.1.4.1.11129.2.1.17", false, extensionBytes);

        return certGen.generate(intermediateKey);
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
