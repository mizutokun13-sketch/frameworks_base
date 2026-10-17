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

import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

/** @hide */
public final class AttestationHooks {
    private static final String PACKAGE_GMS = "com.google.android.gms";
    private static final String PACKAGE_FINSKY = "com.android.vending";
    private static final String PACKAGE_GSF = "com.google.android.gsf";
    private static final String PROCESS_UNSTABLE = "com.google.android.gms.unstable";
    private static final String DATA_FILE = "gms_certified_props.json";

    private static final Set<String> VALID_BUILD_FIELDS = new HashSet<>(Arrays.asList(
        "ID", "DISPLAY", "PRODUCT", "DEVICE", "BOARD", "CPU_ABI", "CPU_ABI2",
        "MANUFACTURER", "BRAND", "MODEL", "SOC_MANUFACTURER", "SOC_MODEL",
        "BOOTLOADER", "RADIO", "HARDWARE", "SKU", "ODM_SKU", "SERIAL",
        "TYPE", "TAGS", "FINGERPRINT", "TIME", "USER", "HOST"
    ));

    private static final Set<String> VALID_VERSION_FIELDS = new HashSet<>(Arrays.asList(
        "INCREMENTAL", "RELEASE", "BASE_OS", "SECURITY_PATCH",
        "MEDIA_PERFORMANCE_CLASS", "SDK", "SDK_INT", "DEVICE_INITIAL_SDK_INT",
        "PREVIEW_SDK_INT", "CODENAME"
    ));

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

        // =========================================================================
        // NHÁNH 1: DÀNH RIÊNG CHO GMS & CH PLAY (PLAY INTEGRITY CERTIFICATION)
        // =========================================================================
        if (PACKAGE_GMS.equals(packageName) || PACKAGE_FINSKY.equals(packageName) || PACKAGE_GSF.equals(packageName)) {
            sIsGms = true;

            if (PROCESS_UNSTABLE.equals(processName) || processName.contains("unstable")) {
                sIsUnstable = true;
            }

            setGmsCertifiedProps();
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
        File pifFile = new File("/data/vendor/keybox/pif.prop");
        if (pifFile.exists()) {
            String content = readFromFile(pifFile);
            if (!TextUtils.isEmpty(content)) {
                loadFromPifProp(content);
            }
        }
    }

    private static boolean loadFromPifProp(String content) {
        if (TextUtils.isEmpty(content)) return false;
        boolean applied = false;
        // Apply FINGERPRINT first so derived defaults can be overridden by explicit keys
        for (String line : content.split("\\r?\\n")) {
            line = line.trim();
            if (line.startsWith("FINGERPRINT=")) {
                applyPropField("FINGERPRINT", line.substring(12).trim());
                applied = true;
                break;
            }
        }
        for (String line : content.split("\\r?\\n")) {
            line = line.trim();
            if (line.isEmpty() || line.startsWith("#")) continue;
            int eq = line.indexOf('=');
            if (eq <= 0) continue;
            String key = line.substring(0, eq).trim();
            String value = line.substring(eq + 1).trim();
            if (!key.isEmpty() && !value.isEmpty()) {
                applyPropField(key, value);
                applied = true;
            }
        }
        return applied;
    }

    private static void applyPropField(String rawKey, String value) {
        if (TextUtils.isEmpty(rawKey) || value == null) return;
        String key = rawKey.trim();
        if (key.startsWith("VERSION.") || key.startsWith("VERSION:")) {
            key = key.substring(8).trim();
        }
        String upperKey = key.toUpperCase();

        // Chỉ chặn ghi đè RELEASE / SDK / SDK_INT cho tiến trình GMS / Play Store (sIsGms)
        // để khớp với KM_TAG_OS_VERSION = 130000 của KeyMint Android 13.
        // Các app bên thứ 3 (WantSpoof / hwcfg) vẫn được spoof RELEASE / SDK_INT bình thường.
        if (sIsGms && ("RELEASE".equals(upperKey) || "SDK".equals(upperKey) || "SDK_INT".equals(upperKey))) {
            return;
        }

        if ("FINGERPRINT".equals(upperKey)) {
            setBuildField("FINGERPRINT", value);
            // Tự động tách các trường chuẩn từ FINGERPRINT: brand/product/device:ver/id/inc:type/tags
            try {
                String[] colonParts = value.split(":");
                if (colonParts.length == 3) {
                    String[] devParts = colonParts[0].split("/");
                    if (devParts.length == 3) {
                        setBuildField("BRAND", devParts[0]);
                        setBuildField("PRODUCT", devParts[1]);
                        setBuildField("DEVICE", devParts[2]);
                    }
                    String[] verParts = colonParts[1].split("/");
                    if (verParts.length == 3) {
                        setBuildField("ID", verParts[1]);
                        setBuildField("DISPLAY", verParts[1]);
                        setVersionField("INCREMENTAL", verParts[2]);
                    }
                    String[] tagParts = colonParts[2].split("/");
                    if (tagParts.length == 2) {
                        setBuildField("TYPE", tagParts[0]);
                        setBuildField("TAGS", tagParts[1]);
                    }
                }
            } catch (Throwable ignored) {}
            return;
        }

        if ("FIRST_API_LEVEL".equals(upperKey) || "DEVICE_INITIAL_SDK_INT".equals(upperKey)) {
            setVersionField("DEVICE_INITIAL_SDK_INT", value);
        } else if (VALID_VERSION_FIELDS.contains(upperKey)) {
            setVersionField(upperKey, value);
        } else if (VALID_BUILD_FIELDS.contains(upperKey)) {
            setBuildField(upperKey, value);
        }
    }

    /**
     * Gán Build Fields động từ profile thống nhất (/data/vendor/hwcfg/profile.json hoặc sys.hwcfg)
     * Nếu không có cấu hình tùy biến -> Giữ nguyên giá trị mặc định của hệ thống ROM.
     */
    private static void spoofAppBuildFields(Context context) {
        // Override Java System.getProperty("os.version") and "os.arch" so apps see spoofed kernel
        try {
            String unameRelease = getHwcfgValue("uname.release");
            if (TextUtils.isEmpty(unameRelease)) {
                unameRelease = readFromFile(new File("/data/vendor/hwcfg/uname.release"));
            }
            if (!TextUtils.isEmpty(unameRelease)) {
                System.setProperty("os.version", unameRelease.trim());
            }
            String unameMachine = getHwcfgValue("uname.machine");
            if (TextUtils.isEmpty(unameMachine)) {
                unameMachine = readFromFile(new File("/data/vendor/hwcfg/uname.machine"));
            }
            if (!TextUtils.isEmpty(unameMachine)) {
                System.setProperty("os.arch", unameMachine.trim());
            }
        } catch (Throwable ignored) {}

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
                        applyPropField(k, v);
                    }
                    if (!obj.has("BOOTLOADER") && !obj.has("bootloader")) {
                        String bl = obj.optString("INCREMENTAL", obj.optString("incremental", ""));
                        if (TextUtils.isEmpty(bl)) bl = obj.optString("ID", obj.optString("buildid", ""));
                        if (TextUtils.isEmpty(bl)) bl = getHwcfgValue("bootloader");
                        if (!TextUtils.isEmpty(bl)) setBuildField("BOOTLOADER", bl);
                    }
                    setBuildField("TYPE", "user");
                    setBuildField("TAGS", "release-keys");
                    return; // Đã nạp thành công từ unified profile
                } catch (Throwable ignored) {}
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
        String bootloader = getHwcfgValue("bootloader");
        if (TextUtils.isEmpty(bootloader)) bootloader = getHwcfgValue("BOOTLOADER");
        if (TextUtils.isEmpty(bootloader)) bootloader = incremental;
        if (TextUtils.isEmpty(bootloader)) bootloader = buildId;

        // Chỉ ghi đè khi có cấu hình cụ thể
        if (!TextUtils.isEmpty(model)) setBuildField("MODEL", model);
        if (!TextUtils.isEmpty(brand)) setBuildField("BRAND", brand);
        if (!TextUtils.isEmpty(manufacturer)) setBuildField("MANUFACTURER", manufacturer);
        if (!TextUtils.isEmpty(device)) setBuildField("DEVICE", device);
        if (!TextUtils.isEmpty(name)) setBuildField("PRODUCT", name);
        if (!TextUtils.isEmpty(fingerprint)) setBuildField("FINGERPRINT", fingerprint);
        if (!TextUtils.isEmpty(socModel)) setBuildField("SOC_MODEL", socModel);
        if (!TextUtils.isEmpty(socMaker)) setBuildField("SOC_MANUFACTURER", socMaker);
        if (!TextUtils.isEmpty(secPatch)) setVersionField("SECURITY_PATCH", secPatch);
        if (!TextUtils.isEmpty(serial)) setBuildField("SERIAL", serial);
        if (!TextUtils.isEmpty(bootloader)) setBuildField("BOOTLOADER", bootloader);
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
            new File("/data/vendor/hwcfg")
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
        } catch (Throwable e) {
            return false;
        }
        return gmsUid == callingUid;
    }

    private static void setBuildField(String key, String value) {
        if (!VALID_BUILD_FIELDS.contains(key)) return;
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
        } catch (Throwable ignored) {}
    }

    private static void setVersionField(String key, Object value) {
        if (!VALID_VERSION_FIELDS.contains(key)) return;
        try {
            Field field = Build.VERSION.class.getDeclaredField(key);
            field.setAccessible(true);
            if (field.getType().equals(Integer.TYPE) && value instanceof String) {
                field.set(null, Integer.parseInt((String) value));
            } else {
                field.set(null, value);
            }
            field.setAccessible(false);
        } catch (Throwable ignored) {}
    }

    public static boolean isGmsProcess() {
        if (sIsGms) return true;
        try {
            String pName = Application.getProcessName();
            if (pName != null && (pName.startsWith(PACKAGE_GMS) || pName.startsWith(PACKAGE_FINSKY) || pName.startsWith(PACKAGE_GSF))) {
                return true;
            }
        } catch (Throwable ignored) {}
        try {
            String pName = android.app.ActivityThread.currentProcessName();
            if (pName != null && (pName.startsWith(PACKAGE_GMS) || pName.startsWith(PACKAGE_FINSKY) || pName.startsWith(PACKAGE_GSF))) {
                return true;
            }
        } catch (Throwable ignored) {}
        return false;
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
        return false;
    }

    private static String readFromFile(File file) {
        if (file == null || !file.exists() || !file.canRead()) return "";
        StringBuilder content = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line).append("\n");
            }
        } catch (Throwable ignored) {}
        return content.toString().trim();
    }
}

