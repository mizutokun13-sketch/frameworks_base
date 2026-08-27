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

        final boolean spoofGms = SystemProperties.getBoolean("persist.sys.hwcfg.gms", true);

        // =========================================================================
        // NHÁNH 1: DÀNH RIÊNG CHO GMS & CH PLAY (PLAY INTEGRITY CERTIFICATION)
        // =========================================================================
        if (PACKAGE_GMS.equals(packageName) || PACKAGE_FINSKY.equals(packageName) || PACKAGE_GSF.equals(packageName)) {
            sIsGms = true;

            if (PROCESS_UNSTABLE.equals(processName) || processName.contains("unstable")) {
                sIsUnstable = true;
            }

            if (spoofGms) {
                setGmsCertifiedProps();
                setBuildField("TIME", String.valueOf(System.currentTimeMillis()));
            }
            Log.w("GmsAttestTrace", "[INIT GMS] pkg=" + packageName + " proc=" + processName + " spoofGms=" + spoofGms
                    + " MODEL=" + Build.MODEL + " FINGERPRINT=" + Build.FINGERPRINT
                    + " FIRST_API=" + Build.VERSION.DEVICE_INITIAL_SDK_INT);
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
            File tmpFile = new File("/data/local/tmp/gms_certified_props.json");
            if (tmpFile.exists()) {
                savedProps = readFromFile(tmpFile);
            }
        }

        if (TextUtils.isEmpty(savedProps)) {
            setBuildField("BRAND", "google");
            setBuildField("MANUFACTURER", "Google");
            setBuildField("DEVICE", "panther");
            setBuildField("PRODUCT", "panther");
            setBuildField("MODEL", "Pixel 7");
            setBuildField("FINGERPRINT", "google/panther/panther:15/AP4A.250605.005/12854468:user/release-keys");
            setBuildField("ID", "AP4A.250605.005");
            setBuildField("TYPE", "user");
            setBuildField("TAGS", "release-keys");
            setVersionField("INCREMENTAL", "12854468");
            setVersionField("RELEASE", "15");
            setVersionField("DEVICE_INITIAL_SDK_INT", 33);
            setVersionField("SECURITY_PATCH", "2025-06-05");
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
                } else if ("RELEASE".equalsIgnoreCase(key) || "INCREMENTAL".equalsIgnoreCase(key)
                        || "SECURITY_PATCH".equalsIgnoreCase(key) || "DEVICE_INITIAL_SDK_INT".equalsIgnoreCase(key)
                        || "SDK_INT".equalsIgnoreCase(key) || "PREVIEW_SDK_INT".equalsIgnoreCase(key)) {
                    setVersionField(key, value);
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
    /**
     * Gán Build Fields động từ profile thống nhất (/data/vendor/hwcfg/profile.json hoặc sys.hwcfg)
     * Nếu không có cấu hình tùy biến -> Giữ nguyên giá trị mặc định của hệ thống ROM.
     */
    private static void spoofAppBuildFields(Context context) {
        // 1. Đọc profile JSON thống nhất nếu có
        File unifiedProfile = new File("/data/vendor/hwcfg/profile.json");
        if (unifiedProfile.exists()) {
            String jsonContent = readFromFile(unifiedProfile);
            if (!TextUtils.isEmpty(jsonContent)) {
                try {
                    JSONObject obj = new JSONObject(jsonContent);
                    Iterator<String> keys = obj.keys();
                    while (keys.hasNext()) {
                        String k = keys.next();
                        String v = obj.optString(k, "");
                        if (TextUtils.isEmpty(v)) continue;

                        if ("SECURITY_PATCH".equalsIgnoreCase(k) || "RELEASE".equalsIgnoreCase(k)
                                || "INCREMENTAL".equalsIgnoreCase(k) || "SDK_INT".equalsIgnoreCase(k)) {
                            setVersionField(k.toUpperCase(), v);
                        } else {
                            setBuildField(k.toUpperCase(), v);
                        }
                    }
                    return; // Đã nạp thành công từ unified profile
                } catch (Exception e) {
                    Log.e(TAG, "Lỗi phân giải /data/vendor/hwcfg/profile.json", e);
                }
            }
        }

        // 2. Đọc theo từng trường từ sys.hwcfg.* hoặc /data/vendor/hwcfg/<key>
        String model = getHwcfgValue("model");
        String brand = getHwcfgValue("brand");
        String device = getHwcfgValue("device");
        String name = getHwcfgValue("name");
        String manufacturer = getHwcfgValue("manufacturer");
        String fingerprint = getHwcfgValue("fingerprint");
        String socModel = getHwcfgValue("socmodel");
        String socMaker = getHwcfgValue("socmaker");
        String secPatch = getHwcfgValue("securitypatch");
        String serial = getHwcfgValue("serial");
        if (TextUtils.isEmpty(serial)) serial = getHwcfgValue("SerialNo");
        String board = getHwcfgValue("board");
        String hardware = getHwcfgValue("hardware");
        String buildId = getHwcfgValue("buildid");
        String displayId = getHwcfgValue("displayid");
        String incremental = getHwcfgValue("incremental");
        String baseband = getHwcfgValue("baseband");

        // Chỉ ghi đè khi người dùng có cấu hình cụ thể
        if (!TextUtils.isEmpty(model)) setBuildField("MODEL", model);
        if (!TextUtils.isEmpty(brand)) setBuildField("BRAND", brand);
        if (!TextUtils.isEmpty(manufacturer)) setBuildField("MANUFACTURER", manufacturer);
        if (!TextUtils.isEmpty(device)) setBuildField("DEVICE", device);
        if (!TextUtils.isEmpty(name)) setBuildField("PRODUCT", name);
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

        // Luôn bảo đảm cờ bảo mật release-keys
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
            new File("/data/vendor/hwcfg"),
            new File("/data/local/tmp/Utils")
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

    public static boolean isUnstableProcess() {
        return sIsUnstable;
    }

    /**
     * Called when GMS requests certificate chain and no emulated keybox chain is available.
     * Must return true to throw UnsupportedOperationException, forcing software attestation
     * fallback instead of leaking Samsung hardware keystore identity.
     */
    public static boolean onEngineGetCertificateChain() {
        // Always block hardware keystore chain for GMS when keybox emulated chain is unavailable.
        // This prevents Samsung Exynos TEE keymaster from exposing real device identity
        // (Samsung cert chain, serial, IMEI etc.) to Google's Play Integrity servers.
        return true;
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
