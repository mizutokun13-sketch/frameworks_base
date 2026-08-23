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
import android.os.SystemProperties;
import android.text.TextUtils;
import android.util.Log;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;

/** @hide */
public final class AttestationHooks {
    private static final String TAG = "AttestationHooks";
    private static final boolean DEBUG = true;

    private static final String PACKAGE_GMS = "com.google.android.gms";
    private static final String PACKAGE_FINSKY = "com.android.vending";
    private static final String PROCESS_UNSTABLE = "com.google.android.gms.unstable";

    // ---------------------------------------------------------------------------------
    // BỘ HỒ SƠ CERTIFIED GOOGLE PIXEL 5 (ANDROID 13 STOCK - CTS APPROVED PASS 100%)
    // ---------------------------------------------------------------------------------
    private static final Map<String, Object> sPixel5Props = new HashMap<>();
    static {
        sPixel5Props.put("BRAND", "google");
        sPixel5Props.put("MANUFACTURER", "Google");
        sPixel5Props.put("DEVICE", "redfin");
        sPixel5Props.put("PRODUCT", "redfin");
        sPixel5Props.put("MODEL", "Pixel 5");
        sPixel5Props.put("ID", "TQ3A.230901.001");
        sPixel5Props.put("FINGERPRINT", "google/redfin/redfin:13/TQ3A.230901.001/10750766:user/release-keys");
        sPixel5Props.put("TYPE", "user");
        sPixel5Props.put("TAGS", "release-keys");
    }

    private static volatile boolean sIsGms = false;
    private static volatile String sProcessName;

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
        if (PACKAGE_GMS.equals(packageName) || PACKAGE_FINSKY.equals(packageName)) {
            sIsGms = true;
            sProcessName = processName;

            // 1. Tiến trình DroidGuard kiểm tra tính toàn vẹn (SafetyNet / Play Integrity)
            if (PROCESS_UNSTABLE.equals(processName) || processName.contains("unstable")) {
                if (DEBUG) Log.d(TAG, "[" + processName + "] Ép Fallback Software Basic Attestation");
                // Đặt FIRST_API_LEVEL = 30 (Android 11) để Google Server không đòi hỏi StrongBox KeyMint phần cứng
                setVersionField("DEVICE_INITIAL_SDK_INT", 30);
            }

            // 2. Gán toàn bộ Fingerprint Certified của Pixel 5 cho GMS
            if (DEBUG) Log.d(TAG, "[" + processName + "] Gán Profile Certified Pixel 5 cho GMS");
            for (Map.Entry<String, Object> entry : sPixel5Props.entrySet()) {
                setBuildField(entry.getKey(), String.valueOf(entry.getValue()));
            }

            // Ngày vá bảo mật khớp với bản build TQ3A.230901.001 của Pixel 5
            setVersionField("SECURITY_PATCH", "2023-09-05");
            setBuildField("TIME", String.valueOf(System.currentTimeMillis()));
            return;
        }

        // =========================================================================
        // NHÁNH 2: DÀNH CHO TẤT CẢ APP BÊN THỨ 3 (DÙNG PROFILE TỪ WANTSPOOF / HWCFG)
        // =========================================================================
        if (!"com.wantphone.wantspoof".equals(packageName)) {
            spoofAppBuildFields(context);
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

    public static void onEngineGetCertificateChain() {
        // Chặn Hardware Key Attestation trong GMS unstable process
        // Ép Google Play Integrity đánh giá bằng Basic/Software Attestation
        if (sIsGms) {
            if (DEBUG) Log.d(TAG, "[" + (sProcessName != null ? sProcessName : "GMS") + "] Chặn Hardware KeyMint -> Ép Basic Attestation");
            throw new UnsupportedOperationException();
        }
    }

    private static void setBuildField(String key, String value) {
        try {
            Field field = Build.class.getDeclaredField(key);
            field.setAccessible(true);
            field.set(null, value);
            field.setAccessible(false);
        } catch (Exception e) {
            Log.e(TAG, "Lỗi gán Build." + key + ": " + e.getMessage());
        }
    }

    private static void setVersionField(String key, Object value) {
        try {
            Field field = Build.VERSION.class.getDeclaredField(key);
            field.setAccessible(true);
            field.set(null, value);
            field.setAccessible(false);
        } catch (Exception e) {
            Log.e(TAG, "Lỗi gán Build.VERSION." + key + ": " + e.getMessage());
        }
    }

    public static boolean isGmsProcess() {
        return sIsGms;
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
