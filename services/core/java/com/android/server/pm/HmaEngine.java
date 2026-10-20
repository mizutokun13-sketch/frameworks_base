/*
 * Copyright (C) 2026 WantSpoof Project / Android Open Source Project
 *
 * WantSpoof HideMyApplist (HMA) Engine: ROM-Level Package Visibility & Installer Spoofing
 * Based on Hide My Applist (HMA-OSS) concepts embedded natively into system_server.
 */

package com.android.server.pm;

import android.annotation.NonNull;
import android.annotation.Nullable;
import android.os.Process;
import android.os.SystemProperties;
import android.os.UserHandle;
import android.text.TextUtils;
import android.util.ArrayMap;
import android.util.ArraySet;
import android.util.Slog;

import com.android.server.pm.pkg.PackageStateInternal;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.Arrays;
import java.util.Map;
import java.util.Set;

/**
 * High-performance, zero-overhead ROM-level HideMyApplist engine.
 * Supports per-app Blacklist / Whitelist modes and Installer Spoofing.
 */
public final class HmaEngine {
    private static final String TAG = "WantSpoof_HMA";
    private static final boolean DEBUG = false;

    public static final int MODE_DISABLED = 0;
    public static final int MODE_BLACKLIST = 1;
    public static final int MODE_WHITELIST = 2;

    private static final File[] CONFIG_DIRS = new File[] {
        new File("/data/vendor/hwcfg/hma"),
        new File("/data/vendor/hwcfg/active/hma"),
        new File("/data/system/hma"),
        new File("/data/data/com.wantphone.wantspoof/files/hma"),
        new File("/sdcard/WantSpoof/hma")
    };

    // Default blacklist of sensitive mod / root / test tools
    public static final ArraySet<String> DEFAULT_BLACKLIST = new ArraySet<>(Arrays.asList(
        "bin.mt.plus",
        "bin.mt.plus.canary",
        "me.weishu.kernelsu",
        "com.rifsxd.ksunext",
        "com.topjohnwu.magisk",
        "io.github.vvb2060.magisk",
        "org.lsposed.manager",
        "org.meowcat.edxposed.manager",
        "de.robv.android.xposed.installer",
        "com.chelpus.luckypatcher",
        "com.noshufou.android.su",
        "com.koushikdutta.superuser",
        "eu.chainfire.supersu",
        "com.wantphone.wantspoof",
        "com.inspector.deviceaudit",
        "com.romchecker.adbtest",
        "com.termux",
        "com.guoshi.httpcanary",
        "app.greyshirts.sslcapture",
        "catch_.me_.if_.you_.can_",
        "com.mwr.dz",
        "org.adaway",
        // Cloner & Parallel Space apps
        "org.derpfest.parallelspace",
        "com.lbe.parallel.intl",
        "com.lbe.parallel.intl.arm64",
        "com.lbe.parallel",
        "com.excelliance.dualaid",
        "com.polestar.super.clone",
        "com.applisto.appcloner",
        "com.cloneapp.parallelspace.dualspace",
        "com.vphonegaga.titan",
        "com.f1player",
        "com.x8zs.sandbox",
        "com.twoyi",
        "com.gspace.android",
        // Custom ROM packages — hide from detection apps
        "org.lineageos.updater",
        "org.lineageos.recorder",
        "org.lineageos.setupwizard",
        "org.lineageos.jelly",
        "org.lineageos.etar",
        "org.derpfest.flash",
        "org.derpfest.prospect",
        "org.derpfest.walls",
        "io.chaldeaprjkt.gamespace"
    ));

    // Default target packages protected by HMA & installer spoofing
    public static final ArraySet<String> DEFAULT_TARGETS = new ArraySet<>(Arrays.asList(
        "com.mbmobile",
        "com.shopee.vn",
        "com.ss.android.ugc.trill",
        "com.zhiliaoapp.musically",
        "com.twitter.android",
        "com.vnid",
        "com.vnpay.bidv",
        "com.vcombank.vcbdigibank",
        "com.techcombank.mobile",
        "com.zing.zalo",
        "com.eltavine.duckdetector"
    ));

    public static class AppScopeConfig {
        public int mode = MODE_BLACKLIST; // 1: blacklist, 2: whitelist
        public boolean useDefaultBlacklist = true;
        public final Set<String> customList = new ArraySet<>();
        public String spoofInstaller = "com.android.vending";
    }

    private static final Object sLock = new Object();
    private static boolean sEnabled = true;
    private static long sLastCheckTime = 0;
    private static long sLastConfigFileMod = 0;
    private static String sLastReloadProp = "";
    private static String sCachedSeed = "";
    private static long sCachedProfileTimestamp = 0L;
    private static final Map<String, AppScopeConfig> sScopes = new ArrayMap<>();
    private static final Set<String> sGlobalBlacklist = new ArraySet<>(DEFAULT_BLACKLIST);

    private static String readSmallFileTrimmed(File f) {
        if (!f.exists() || !f.canRead()) return "";
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            String line = br.readLine();
            return line != null ? line.trim() : "";
        } catch (Exception ignored) {
            return "";
        }
    }

    private static void refreshProfileSeedLocked() {
        String seed = readSmallFileTrimmed(new File("/data/vendor/hwcfg/seed"));
        if (TextUtils.isEmpty(seed)) {
            seed = SystemProperties.get("sys.hwcfg.serial",
                    SystemProperties.get("persist.sys.hwcfg.serial", ""));
        }
        sCachedSeed = seed != null ? seed.trim() : "";

        long ts = 0L;
        String tsStr = readSmallFileTrimmed(new File("/data/vendor/hwcfg/timestamp"));
        if (TextUtils.isEmpty(tsStr)) {
            tsStr = SystemProperties.get("sys.hwcfg.reload",
                    SystemProperties.get("persist.sys.hwcfg.reload", ""));
        }
        if (!TextUtils.isEmpty(tsStr)) {
            try {
                ts = Long.parseLong(tsStr.trim());
            } catch (NumberFormatException ignored) {}
        }
        if (ts <= 0L) {
            File seedFile = new File("/data/vendor/hwcfg/seed");
            if (seedFile.exists()) {
                ts = seedFile.lastModified();
            }
        }
        sCachedProfileTimestamp = ts;
    }

    private static void ensureDefaultTargetsLocked() {
        for (String target : DEFAULT_TARGETS) {
            if (!sScopes.containsKey(target)) {
                AppScopeConfig cfg = new AppScopeConfig();
                cfg.mode = MODE_BLACKLIST;
                cfg.useDefaultBlacklist = true;
                cfg.spoofInstaller = "com.android.vending";
                sScopes.put(target, cfg);
            }
        }
    }

    private static void checkAndReloadConfigLocked() {
        long now = System.currentTimeMillis();
        String reloadProp = SystemProperties.get("sys.hwcfg.reload",
                SystemProperties.get("persist.sys.hwcfg.reload", ""));

        // Only poll filesystem at most once every 3 seconds unless property changed
        if (now - sLastCheckTime < 3000 && reloadProp.equals(sLastReloadProp)) {
            return;
        }
        sLastCheckTime = now;
        sLastReloadProp = reloadProp;
        refreshProfileSeedLocked();

        File configFile = null;
        for (File dir : CONFIG_DIRS) {
            File f = new File(dir, "config.json");
            if (f.exists()) {
                configFile = f;
                break;
            }
        }

        if (configFile == null) {
            // Check legacy scope folder
            for (File dir : CONFIG_DIRS) {
                File scopeDir = new File(dir, "scopes");
                if (scopeDir.exists() && scopeDir.isDirectory()) {
                    loadFromScopeDirectory(scopeDir);
                    return;
                }
            }
            // If no config directory configured, default scopes for top banking/security apps
            if (sScopes.isEmpty()) {
                setupDefaultScopes();
            }
            return;
        }

        long lastMod = configFile.lastModified();
        if (lastMod == sLastConfigFileMod) {
            return;
        }
        sLastConfigFileMod = lastMod;

        try (BufferedReader reader = new BufferedReader(new FileReader(configFile))) {
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line);
            }
            parseJsonConfig(sb.toString());
        } catch (Exception e) {
            Slog.e(TAG, "Lỗi đọc file cấu hình HMA JSON: " + configFile, e);
        }
    }

    private static void setupDefaultScopes() {
        sScopes.clear();
        sGlobalBlacklist.clear();
        sGlobalBlacklist.addAll(DEFAULT_BLACKLIST);
        ensureDefaultTargetsLocked();
    }

    private static void loadFromScopeDirectory(File scopeDir) {
        sScopes.clear();
        File[] files = scopeDir.listFiles();
        if (files != null) {
            for (File f : files) {
                String pkg = f.getName();
                if (pkg.endsWith(".list") || pkg.endsWith(".txt")) {
                    pkg = pkg.substring(0, pkg.lastIndexOf('.'));
                }
                AppScopeConfig cfg = new AppScopeConfig();
                cfg.mode = MODE_BLACKLIST;
                cfg.useDefaultBlacklist = true;
                cfg.spoofInstaller = "com.android.vending";

                try (BufferedReader br = new BufferedReader(new FileReader(f))) {
                    String line;
                    while ((line = br.readLine()) != null) {
                        line = line.trim();
                        if (line.isEmpty() || line.startsWith("#")) continue;
                        if (line.startsWith("mode=")) {
                            String m = line.substring(5).toLowerCase();
                            if (m.equals("whitelist") || m.equals("2")) cfg.mode = MODE_WHITELIST;
                            else if (m.equals("disabled") || m.equals("0")) cfg.mode = MODE_DISABLED;
                        } else if (line.startsWith("installer=")) {
                            cfg.spoofInstaller = line.substring(10).trim();
                        } else {
                            cfg.customList.add(line);
                        }
                    }
                } catch (IOException ignored) {}
                sScopes.put(pkg, cfg);
            }
        }
        ensureDefaultTargetsLocked();
    }

    private static void parseJsonConfig(String jsonStr) {
        try {
            JSONObject root = new JSONObject(jsonStr);
            sEnabled = root.optBoolean("enabled", true);
            if (!sEnabled) {
                sScopes.clear();
                return;
            }

            sGlobalBlacklist.clear();
            sGlobalBlacklist.addAll(DEFAULT_BLACKLIST);
            JSONArray globalList = root.optJSONArray("default_blacklist");
            if (globalList != null) {
                for (int i = 0; i < globalList.length(); i++) {
                    sGlobalBlacklist.add(globalList.getString(i));
                }
            }

            sScopes.clear();
            JSONObject scopesObj = root.optJSONObject("scopes");
            if (scopesObj != null) {
                java.util.Iterator<String> keys = scopesObj.keys();
                while (keys.hasNext()) {
                    String callerPkg = keys.next();
                    JSONObject appObj = scopesObj.getJSONObject(callerPkg);
                    AppScopeConfig cfg = new AppScopeConfig();

                    String modeStr = appObj.optString("mode", "blacklist");
                    if ("whitelist".equalsIgnoreCase(modeStr) || "2".equals(modeStr)) {
                        cfg.mode = MODE_WHITELIST;
                    } else if ("disabled".equalsIgnoreCase(modeStr) || "0".equals(modeStr)) {
                        cfg.mode = MODE_DISABLED;
                    } else {
                        cfg.mode = MODE_BLACKLIST;
                    }

                    cfg.useDefaultBlacklist = appObj.optBoolean("use_default_blacklist", true);
                    cfg.spoofInstaller = appObj.optString("spoof_installer", "com.android.vending");

                    JSONArray list = appObj.optJSONArray("list");
                    if (list == null) list = appObj.optJSONArray("blacklist");
                    if (list == null) list = appObj.optJSONArray("whitelist");

                    if (list != null) {
                        for (int i = 0; i < list.length(); i++) {
                            cfg.customList.add(list.getString(i));
                        }
                    }
                    sScopes.put(callerPkg, cfg);
                }
            }
            ensureDefaultTargetsLocked();
        } catch (Exception e) {
            Slog.e(TAG, "Lỗi phân giải JSON config HMA", e);
        }
    }

    /**
     * Core decision engine called from ComputerEngine#shouldFilterApplication
     * Returns true if target package should be HIDDEN from calling UID.
     */
    public static boolean shouldFilterForCaller(@NonNull ComputerEngine engine,
                                                @NonNull PackageStateInternal targetPs,
                                                int callingUid, int userId) {
        if (UserHandle.getAppId(callingUid) < Process.FIRST_APPLICATION_UID) {
            return false; // System UID can see everything
        }

        String targetPkg = targetPs.getPackageName();
        if (TextUtils.isEmpty(targetPkg)) {
            return false;
        }

        // Get calling package name
        String callerPkg = engine.getNameForUid(callingUid);
        if (callerPkg != null && callerPkg.contains(":")) {
            callerPkg = callerPkg.substring(0, callerPkg.indexOf(':'));
        }

        if (TextUtils.isEmpty(callerPkg)) {
            return false;
        }

        // App can always see itself
        if (callerPkg.equals(targetPkg)) {
            return false;
        }

        synchronized (sLock) {
            checkAndReloadConfigLocked();
            if (!sEnabled) {
                return false;
            }

            AppScopeConfig cfg = sScopes.get(callerPkg);
            if (cfg == null || cfg.mode == MODE_DISABLED) {
                // Not in HMA scope -> normal Android behavior
                return false;
            }

            // Mode 1: BLACKLIST MODE
            if (cfg.mode == MODE_BLACKLIST) {
                if (cfg.useDefaultBlacklist) {
                    if (sGlobalBlacklist.contains(targetPkg) || isSensitivePrefix(targetPkg)) {
                        return true; // HIDE
                    }
                }
                if (cfg.customList.contains(targetPkg)) {
                    return true; // HIDE
                }
                return false; // Show everything else
            }

            // Mode 2: WHITELIST MODE
            if (cfg.mode == MODE_WHITELIST) {
                // System apps are generally allowed unless strictly blacklisted
                if (targetPs.isSystem()) {
                    return false;
                }
                if (cfg.customList.contains(targetPkg)) {
                    return false; // In whitelist -> ALLOW
                }
                return true; // NOT in whitelist -> HIDE
            }
        }

        return false;
    }

    /**
     * Check if installer should be spoofed for calling package.
     */
    @Nullable
    public static String getSpoofedInstaller(@NonNull ComputerEngine engine,
                                            @NonNull String targetPkg,
                                            int callingUid) {
        if (UserHandle.getAppId(callingUid) < Process.FIRST_APPLICATION_UID) {
            return null;
        }

        String callerPkg = engine.getNameForUid(callingUid);
        if (callerPkg != null && callerPkg.contains(":")) {
            callerPkg = callerPkg.substring(0, callerPkg.indexOf(':'));
        }

        if (TextUtils.isEmpty(callerPkg)) {
            return null;
        }

        synchronized (sLock) {
            checkAndReloadConfigLocked();
            if (!sEnabled) return null;

            AppScopeConfig cfg = sScopes.get(callerPkg);
            if (cfg != null && !TextUtils.isEmpty(cfg.spoofInstaller)) {
                return cfg.spoofInstaller;
            }
        }
        return null;
    }

    /**
     * Spoof firstInstallTime and lastUpdateTime deterministically per active WantSpoof profile
     * (seed & profile creation timestamp) for non-exempt 3rd-party callers.
     */
    @Nullable
    public static long[] getSpoofedPackageTimes(@NonNull ComputerEngine engine,
                                                @NonNull String targetPkg,
                                                boolean isSystemPkg,
                                                long realFirstInstallTime,
                                                long realLastUpdateTime,
                                                int callingUid) {
        if (UserHandle.getAppId(callingUid) < Process.FIRST_APPLICATION_UID) {
            return null;
        }

        String enabledProp = SystemProperties.get("sys.hwcfg.enabled",
                SystemProperties.get("persist.sys.hwcfg.enabled", "1"));
        if ("0".equals(enabledProp)) {
            return null;
        }

        String callerPkg = engine.getNameForUid(callingUid);
        if (callerPkg != null && callerPkg.contains(":")) {
            callerPkg = callerPkg.substring(0, callerPkg.indexOf(':'));
        }
        if (TextUtils.isEmpty(callerPkg)) {
            return null;
        }

        // Exempt GMS, Play Store, Settings, and WantSpoof manager
        if ("com.google.android.gms".equals(callerPkg)
                || "com.android.vending".equals(callerPkg)
                || "com.google.android.gsf".equals(callerPkg)
                || "com.android.settings".equals(callerPkg)
                || "com.wantphone.wantspoof".equals(callerPkg)) {
            return null;
        }

        String seed;
        long profileTs;
        synchronized (sLock) {
            checkAndReloadConfigLocked();
            seed = sCachedSeed;
            profileTs = sCachedProfileTimestamp;
        }

        if (TextUtils.isEmpty(seed)) {
            return null;
        }

        long now = System.currentTimeMillis();
        long baseTs = (profileTs > 1577836800000L && profileTs <= now) ? profileTs : now;

        // 64-bit FNV-1a hash of (seed + ":" + targetPkg)
        long hash = 0xcbf29ce484222325L;
        String input = seed + ":" + targetPkg;
        for (int i = 0; i < input.length(); i++) {
            hash ^= input.charAt(i);
            hash *= 0x100000001b3L;
        }
        long absHash = hash == Long.MIN_VALUE ? 0L : Math.abs(hash);

        if (isSystemPkg) {
            // Align system packages with WantSpoof's ROM build timestamp (baseTs - 30 days)
            long sysBuildTime = baseTs - 2592000000L;
            return new long[] { sysBuildTime, sysBuildTime };
        }

        // User-installed package: fresh install aligned with profile creation timestamp
        long jitterMs = 15_000L + (absHash % 240_000L);
        long spoofedTime = baseTs - jitterMs;
        if (spoofedTime > now - 5_000L) {
            spoofedTime = now - 5_000L - (absHash % 30_000L);
        }
        return new long[] { spoofedTime, spoofedTime };
    }

    private static boolean isSensitivePrefix(String pkg) {
        return pkg.startsWith("bin.mt.") ||
               pkg.startsWith("com.topjohnwu.") ||
               pkg.startsWith("org.lsposed.") ||
               pkg.startsWith("me.weishu.kernelsu") ||
               pkg.startsWith("com.rifsxd.ksu") ||
               pkg.startsWith("org.derpfest.") ||
               pkg.startsWith("com.derp.") ||
               pkg.startsWith("org.lineageos.") ||
               pkg.startsWith("com.lbe.parallel");
    }
}
