// Multi-source profile support: /data/vendor/hwcfg/active/Utils/ -> /data/local/tmp/Utils/ -> /system/Utils/
// Dynamic reload via gsm.hwcfg.reload property change.

#include "hwcfg.h"

#include <cutils/properties.h>
#include <cerrno>
#include <unistd.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <mutex>
#include <sstream>
#include <string>

#define AID_APP_START 10000

namespace hwcfg {

namespace {

std::mutex g_lock;
int g_pid = -1;
int g_state = 0;    // 0 unknown, 1 enabled, -1 disabled
std::string g_last_reload_ts = "";
std::map<std::string, std::string> g_cache;

std::string readFile(const char* path, size_t cap = 0x100000) {
    FILE* f = fopen(path, "rb");
    if (!f) return {};
    std::string s;
    char buf[4096];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
        s.append(buf, n);
        if (s.size() > cap) break;
    }
    fclose(f);
    return s;
}

bool is_exempt_process() {
    const char* prog = getprogname();
    if (!prog || !*prog) return false;
    return strstr(prog, "com.google.android.gms") != nullptr ||
           strstr(prog, "com.android.vending") != nullptr ||
           strstr(prog, "com.google.android.gsf") != nullptr ||
           strstr(prog, "com.wantphone.wantspoof") != nullptr ||
           strstr(prog, "com.android.systemui") != nullptr ||
           strstr(prog, "com.android.launcher3") != nullptr ||
           strstr(prog, "android.process.media") != nullptr ||
           strstr(prog, "com.android.mtp") != nullptr;
}

bool is_zygote_preinit() {
    const char* prog = getprogname();
    if (!prog || !*prog) return true;
    return !strncmp(prog, "zygote", 6) ||
           !strncmp(prog, "usap", 4) ||
           !strncmp(prog, "app_process", 11) ||
           !strcmp(prog, "<pre-initialized>");
}

// Activation: the flag file exists or fallback to system utils or app UID >= 10000.
bool is_enabled() {
    int pid = getpid();
    if (g_pid != pid) { g_pid = pid; g_state = 0; g_cache.clear(); }  // re-check per fork

    // Always check exemption dynamically in case setArgV0 ran after fork
    if (is_exempt_process()) {
        g_state = -1;
        return false;
    }
    if (is_zygote_preinit() && getuid() >= AID_APP_START) {
        return false;
    }
    if (g_state) return g_state == 1;

    // 0. System processes (system_server, com.android.systemui, etc.) must NEVER be spoofed
    if (getuid() < AID_APP_START && getuid() != 0) {
        g_state = -1; // disabled
        return false;
    }

    // 1. Always enabled for non-exempt 3rd party apps
    if (getuid() >= AID_APP_START) {
        g_state = 1;
        return true;
    }

    // 2. Check system properties
    char enabled_prop[PROPERTY_VALUE_MAX] = {0};
    property_get("sys.hwcfg.enabled", enabled_prop, "");
    if (enabled_prop[0] == 0) {
        property_get("persist.sys.hwcfg.enabled", enabled_prop, "");
    }
    if (!strcmp(enabled_prop, "1") || !strcmp(enabled_prop, "true")) {
        g_state = 1;
        return true;
    }

    std::string flag = readFile("/data/vendor/hwcfg/seed");
    if (flag.empty()) {
        flag = readFile("/data/vendor/hwcfg/model");
    }
    if (flag.empty()) {
        flag = readFile("/data/vendor/hwcfg/imei");
    }
    // trim so a file of only whitespace counts as empty/off
    size_t e = flag.find_last_not_of(" \t\r\n");
    g_state = (e == std::string::npos) ? -1 : 1;
    return g_state == 1;
}

struct PropPair { const char* prop; const char* field; };
// Property map mapping system properties to spoofed Utils keys
static const PropPair kPropMap[] = {
    {"gsm.hwcfg.imei","imei"},{"gsm.hwcfg.meid","meid"},{"gsm.hwcfg.imsi","imsi"},
    {"gsm.hwcfg.iccid","iccid"},{"gsm.hwcfg.operator","carrier"},
    {"gsm.hwcfg.opname","carrier"},{"gsm.hwcfg.line1","phonenumber"},
    {"gsm.operator.numeric","mccmnc"},{"gsm.operator.alpha","carrier"},
    {"gsm.operator.iso-country","country_iso"},
    {"gsm.sim.operator.numeric","mccmnc"},{"gsm.sim.operator.alpha","carrier"},
    {"gsm.sim.operator.iso-country","country_iso"},{"gsm.hwcfg.country","country_iso"},
    {"persist.sys.country","country_iso"},{"wlan.hwcfg.mac","mac"},
    {"wlan.hwcfg.ssid","ssid"},{"wlan.hwcfg.bssid","bssid"},
    {"ro.serialno","serial"},{"ro.boot.serialno","serial"},
    {"ro.boot.verifiedbootstate","verifiedbootstate"},{"ro.boot.flash.locked","flashlocked"},
    {"ro.boot.vbmeta.device_state","vbmetastate"},{"ro.boot.veritymode","veritymode"},
    {"ro.boot.warranty_bit","warranty_bit"},{"ro.warranty_bit","warranty_bit"},
    {"ro.boot.selinux","selinux"},
    {"ro.product.model","model"},{"ro.product.system.model","model"},
    {"ro.product.vendor.model","model"},{"ro.product.odm.model","model"},
    {"ro.product.brand","brand"},{"ro.product.system.brand","brand"},
    {"ro.product.vendor.brand","brand"},{"ro.product.device","device"},
    {"ro.product.system.device","device"},{"ro.product.vendor.device","device"},
    {"ro.product.name","name"},{"ro.product.system.name","name"},{"ro.build.product","name"},
    {"ro.product.manufacturer","manufacturer"},{"ro.product.system.manufacturer","manufacturer"},
    {"ro.product.vendor.manufacturer","manufacturer"},{"ro.build.fingerprint","fingerprint"},
    {"ro.system.build.fingerprint","fingerprint"},{"ro.vendor.build.fingerprint","fingerprint"},
    {"ro.product.build.fingerprint","fingerprint"},{"ro.odm.build.fingerprint","fingerprint"},
    {"ro.bootimage.build.fingerprint","fingerprint"},{"ro.product.bootimage.model","model"},
    {"ro.product.bootimage.device","device"},{"ro.product.bootimage.name","name"},
    {"ro.boot.em.model","model"},{"ro.build.description","description"},
    {"ro.system.build.description","description"},{"ro.vendor.build.description","description"},
    {"ro.bootimage.build.description","description"},{"ro.product.board","board"},
    {"ro.hardware","hardware"},{"ro.boot.hardware","hardware"},{"ro.board.platform","platform"},
    {"ro.hardware.chipname","socmodel"},{"ro.soc.model","socmodel"},
    {"ro.soc.manufacturer","socmaker"},{"gsm.version.baseband","baseband"},
    {"ro.bootloader","bootloader"},{"ro.boot.bootloader","bootloader"},
    {"ril.sw_ver","baseband"},{"ril.modem.board","platform"},
    {"ril.model_id","model"},{"ril.hw_ver","bootloader"},{"ril.rfcal_date","builddateutc"},
    {"ro.build.flavor","description"},
    {"ro.build.host","buildhost"},{"ro.build.user","builduser"},{"ro.build.id","buildid"},
    {"ro.build.display.id","displayid"},{"ro.system.build.display.id","displayid"},
    {"ro.vendor.build.display.id","displayid"},{"ro.odm.build.display.id","displayid"},
    {"ro.build.version.incremental","incremental"},
    {"ro.build.date","builddate"},{"ro.build.date.utc","builddateutc"},
    {"ro.bootimage.build.date","builddate"},{"ro.bootimage.build.date.utc","builddateutc"},
    {"ro.vendor.build.date","builddate"},{"ro.vendor.build.date.utc","builddateutc"},
    {"ro.build.version.security_patch","securitypatch"},
    {"ro.vendor.build.security_patch","securitypatch"},{"ro.derp.version","displayid"},
    {"gsm.hwcfg.gps.enabled","gps_enabled"},
    {"gsm.hwcfg.lat","lat"},{"gsm.hwcfg.lon","lon"},
    {"gsm.hwcfg.gps.accuracy","gpsAccuracy"},{"gsm.hwcfg.gps.altitude","gpsAltitude"},
    {"gsm.hwcfg.gps.provider","gpsProvider"},{"gsm.hwcfg.gps.speed","gpsSpeed"},
    {"gsm.hwcfg.gps.bearing","gpsBearing"},{"gsm.hwcfg.gps.time","gpsTime"},
    {"gsm.hwcfg.gps.elapsed","gpsElapsedRealtimeNanos"},
    {"sys.hwcfg.gps.accuracy","gpsAccuracy"},{"sys.hwcfg.gps.altitude","gpsAltitude"},
    {"sys.hwcfg.gps.provider","gpsProvider"},{"sys.hwcfg.gps.speed","gpsSpeed"},
    {"sys.hwcfg.gps.bearing","gpsBearing"},{"sys.hwcfg.gps.time","gpsTime"},
    {"sys.hwcfg.gps.elapsed","gpsElapsedRealtimeNanos"},
    {"persist.sys.hwcfg.gps.accuracy","gpsAccuracy"},
    {"persist.sys.hwcfg.gps.altitude","gpsAltitude"},
    {"persist.sys.hwcfg.gps.provider","gpsProvider"},
    {"persist.sys.hwcfg.gps.speed","gpsSpeed"},
    {"persist.sys.hwcfg.gps.bearing","gpsBearing"},
    {"persist.sys.hwcfg.gps.time","gpsTime"},
    {"persist.sys.hwcfg.gps.elapsed","gpsElapsedRealtimeNanos"},
    {"sys.hwcfg.drm.unique","drmUniqueId"},{"persist.sys.hwcfg.drm.unique","drmUniqueId"},
    {"gsm.hwcfg.drm.unique","drmUniqueId"},
    {"gsm.hwcfg.batt.level","battlevel"},{"gsm.hwcfg.batt.temp","batttemp"},
    {"gsm.hwcfg.batt.volt","battvolt"},{"ro.build.version.oneui","oneui"},
    {"ro.build.version.sem_platform_int","sepint"},{"ro.csc.sales_code","csc"},
    {"ro.boot.sales_code","csc"},{"ril.sales_code","csc"},
    {"ro.csc.countryiso_code","CountryCode"},{"ril.product_code","productcode"},
    {"ro.product_code","productcode"},{"ro.boot.product_code","productcode"},
    {"ro.vendor.product_code","productcode"},
    {"gsm.hwcfg.screen.w","screenW"},{"gsm.hwcfg.screen.h","screenH"},
    {"gsm.hwcfg.screen.dpi","screenDpi"},{"gsm.hwcfg.screen.brightness","screenBrightness"},
    {"sys.hwcfg.screen.w","screenW"},{"sys.hwcfg.screen.h","screenH"},
    {"sys.hwcfg.screen.dpi","screenDpi"},{"persist.sys.hwcfg.screen.w","screenW"},
    {"persist.sys.hwcfg.screen.h","screenH"},{"persist.sys.hwcfg.screen.dpi","screenDpi"},
    {"ro.runtime.firstboot","firstboot"},
    {"ro.advertising.id","gaid"},{"ro.google.aid","gaid"},
    {"ro.android_id","android_id"},{"ro.boot.android_id","android_id"},
};

const char* aliasField(const char* name) {
    if (!strcmp(name, "screen_w")) return "screenW";
    if (!strcmp(name, "screen_h")) return "screenH";
    if (!strcmp(name, "screen_dpi")) return "screenDpi";
    if (!strcmp(name, "screenW")) return "screen_w";
    if (!strcmp(name, "screenH")) return "screen_h";
    if (!strcmp(name, "screenDpi")) return "screen_dpi";
    if (!strcmp(name, "CountryCode")) return "csciso";
    if (!strcmp(name, "csciso")) return "CountryCode";
    if (!strcmp(name, "productcode")) return "product_code";
    if (!strcmp(name, "product_code")) return "productcode";
    if (!strcmp(name, "firstboot")) return "first_boot";
    if (!strcmp(name, "first_boot")) return "firstboot";
    if (!strcmp(name, "realtime")) return "uptime";
    if (!strcmp(name, "uptime")) return "realtime";
    if (!strcmp(name, "builddateutc")) return "build_date_utc";
    if (!strcmp(name, "build_date_utc")) return "builddateutc";
    if (!strcmp(name, "builddate")) return "build_date";
    if (!strcmp(name, "build_date")) return "builddate";
    if (!strcmp(name, "carrier")) return "SimOperatorName";
    if (!strcmp(name, "SimOperatorName")) return "carrier";
    if (!strcmp(name, "sim_operator")) return "SimOperatorName";
    if (!strcmp(name, "network_operator_name")) return "SimOperatorName";
    if (!strcmp(name, "wifiMac")) return "mac";
    if (!strcmp(name, "mac")) return "wifiMac";
    if (!strcmp(name, "wifiName")) return "ssid";
    if (!strcmp(name, "ssid")) return "wifiName";
    if (!strcmp(name, "bssid")) return "BSSID";
    if (!strcmp(name, "BSSID")) return "bssid";
    if (!strcmp(name, "phonenumber")) return "PhoneNumber";
    if (!strcmp(name, "PhoneNumber")) return "phonenumber";
    if (!strcmp(name, "SimOperator")) return "mccmnc";
    if (!strcmp(name, "mccmnc")) return "SimOperator";
    if (!strcmp(name, "gaid")) return "google_aid";
    if (!strcmp(name, "google_aid")) return "gaid";
    if (!strcmp(name, "advertising_id")) return "gaid";
    if (!strcmp(name, "adid")) return "gaid";
    if (!strcmp(name, "android_id")) return "androidid";
    if (!strcmp(name, "androidid")) return "android_id";
    if (!strcmp(name, "openudid")) return "android_id";
    return nullptr;
}

static void ensure_atfork_registered() {
    static std::once_flag flag;
    std::call_once(flag, []() {
        pthread_atfork(
            []() { g_lock.lock(); },
            []() { g_lock.unlock(); },
            []() {
                g_lock.unlock();
                g_pid = getpid();
                g_state = 0;
                g_cache.clear();
            }
        );
    });
}

}  // namespace

bool enabled() {
    ensure_atfork_registered();
    std::lock_guard<std::mutex> lk(g_lock);
    return is_enabled();
}

std::string get(const char* name) {
    if (!name || !*name) return {};
    ensure_atfork_registered();
    std::lock_guard<std::mutex> lk(g_lock);
    if (!is_enabled()) return {};

    // Dynamic Hot-Reload check: check sys.hwcfg.reload, persist.sys.hwcfg.reload, gsm.hwcfg.reload
    char reload_val[PROPERTY_VALUE_MAX] = {0};
    property_get("sys.hwcfg.reload", reload_val, "");
    if (reload_val[0] == 0) {
        property_get("persist.sys.hwcfg.reload", reload_val, "");
    }
    if (reload_val[0] == 0) {
        property_get("gsm.hwcfg.reload", reload_val, "");
    }
    if (g_last_reload_ts != reload_val) {
        g_last_reload_ts = reload_val;
        g_cache.clear();
    }

    auto it = g_cache.find(name);
    if (it != g_cache.end()) return it->second;

    // 1. Check System Properties: sys.hwcfg.<name> -> persist.sys.hwcfg.<name> and aliases
    char prop_val[PROPERTY_VALUE_MAX] = {0};
    std::string prop_key = "sys.hwcfg.";
    prop_key += name;
    property_get(prop_key.c_str(), prop_val, "");
    if (prop_val[0] == 0) {
        prop_key = "persist.sys.hwcfg.";
        prop_key += name;
        property_get(prop_key.c_str(), prop_val, "");
    }
    if (prop_val[0] == 0) {
        prop_key = "gsm.hwcfg.";
        prop_key += name;
        property_get(prop_key.c_str(), prop_val, "");
    }
    if (prop_val[0] == 0) {
        if (const char* alias = aliasField(name)) {
            prop_key = "sys.hwcfg.";
            prop_key += alias;
            property_get(prop_key.c_str(), prop_val, "");
            if (prop_val[0] == 0) {
                prop_key = "persist.sys.hwcfg.";
                prop_key += alias;
                property_get(prop_key.c_str(), prop_val, "");
            }
            if (prop_val[0] == 0) {
                prop_key = "gsm.hwcfg.";
                prop_key += alias;
                property_get(prop_key.c_str(), prop_val, "");
            }
        }
    }
    if (prop_val[0] != 0) {
        g_cache[name] = prop_val;
        return prop_val;
    }

    // 2. Check File Precedence:
    // Unified single authoritative path
    std::string path = "/data/vendor/hwcfg/";
    path += name;
    std::string v = readFile(path.c_str());

    if (v.empty()) {
        path = "/data/vendor/hwcfg/Utils/";
        path += name;
        v = readFile(path.c_str());
    }

    if (v.empty()) {
        if (const char* alias = aliasField(name)) {
            path = "/data/vendor/hwcfg/";
            path += alias;
            v = readFile(path.c_str());
            if (v.empty()) {
                path = "/data/vendor/hwcfg/Utils/";
                path += alias;
                v = readFile(path.c_str());
            }
        }
    }

    size_t e = v.find_last_not_of(" \t\r\n");     // trim trailing whitespace
    v = (e == std::string::npos) ? std::string() : v.substr(0, e + 1);
    g_cache[name] = v;
    return v;
}

std::string lookupProp(const char* key) {
    if (!key || !*key) return {};

    bool is_app = (getuid() >= AID_APP_START);
    if (is_app || enabled()) {
        if (!strcmp(key, "ro.debuggable"))   return std::string("0");
        if (!strcmp(key, "ro.secure"))       return std::string("1");
        if (!strcmp(key, "ro.build.type"))   return std::string("user");
        if (!strcmp(key, "ro.build.tags"))   return std::string("release-keys");
        if (!strcmp(key, "ro.boot.warranty_bit") || !strcmp(key, "ro.warranty_bit")) return std::string("0");
        if (!strcmp(key, "ro.boot.selinux")) return std::string("enforcing");
    }

    if (!enabled()) {
        if (is_app) {
            if (!strcmp(key, "ro.boot.verifiedbootstate")) return std::string("green");
            if (!strcmp(key, "ro.boot.flash.locked")) return std::string("1");
            if (!strcmp(key, "ro.boot.vbmeta.device_state")) return std::string("locked");
            if (!strcmp(key, "ro.boot.veritymode")) return std::string("enforcing");
            if (!strcmp(key, "ro.crypto.state")) return std::string("encrypted");
            if (!strcmp(key, "ro.crypto.type"))  return std::string("file");
            if (!strcmp(key, "vold.decrypt"))    return std::string("0");
            if (!strcmp(key, "ro.adb.secure"))   return std::string("1");
            if (!strcmp(key, "init.svc.adbd"))   return std::string("stopped");
            if (!strcmp(key, "persist.service.adb.enable")) return std::string("0");
        }
        return {};
    }

    // App isolation & boot security protection
    if (!strcmp(key, "ro.boot.verifiedbootstate")) {
        std::string v = get("verifiedbootstate");
        return v.empty() ? std::string("green") : v;
    }
    if (!strcmp(key, "ro.boot.flash.locked")) {
        std::string v = get("flashlocked");
        return v.empty() ? std::string("1") : v;
    }
    if (!strcmp(key, "ro.boot.vbmeta.device_state")) {
        std::string v = get("vbmetastate");
        return v.empty() ? std::string("locked") : v;
    }
    if (!strcmp(key, "ro.boot.veritymode")) {
        std::string v = get("veritymode");
        return v.empty() ? std::string("enforcing") : v;
    }
    if (!strcmp(key, "ro.serialno") || !strcmp(key, "ro.boot.serialno")) {
        std::string s = get("SerialNo");
        return s.empty() ? get("serial") : s;
    }

    if (!strcmp(key, "ro.product.board")) {
        std::string b = get("board");
        return b.empty() ? get("device") : b;
    }
    if (!strcmp(key, "ro.board.platform")) {
        std::string p = get("platform");
        if (!p.empty()) return p;
        p = get("hardware");
        if (!p.empty()) return p;
        return get("board");
    }
    if (!strcmp(key, "ro.hardware") || !strcmp(key, "ro.boot.hardware")) {
        std::string h = get("hardware");
        if (!h.empty()) return h;
        h = get("platform");
        if (!h.empty()) return h;
        return get("board");
    }
    if (!strcmp(key, "ro.hardware.chipname") || !strcmp(key, "ro.soc.model")) {
        std::string sm = get("chipname");
        if (!sm.empty()) return sm;
        sm = get("socmodel");
        if (!sm.empty()) return sm;
        std::string p = get("platform");
        if (!p.empty()) return p;
        return get("hardware");
    }
    if (!strcmp(key, "ro.soc.manufacturer")) {
        return get("socmaker");
    }

    if (!strcmp(key, "ro.build.id") || !strcmp(key, "ro.system.build.id") ||
        !strcmp(key, "ro.vendor.build.id") || !strcmp(key, "ro.odm.build.id")) {
        std::string bid = get("buildid");
        return bid.empty() ? get("id") : bid;
    }
    if (!strcmp(key, "ro.build.display.id") || !strcmp(key, "ro.derp.version")) {
        std::string d = get("displayid");
        if (!d.empty()) return d;
        d = get("display");
        if (!d.empty()) return d;
        return get("incremental");
    }
    if (!strcmp(key, "ro.build.version.incremental") || !strcmp(key, "ro.system.build.version.incremental") ||
        !strcmp(key, "ro.vendor.build.version.incremental")) {
        return get("incremental");
    }
    if (!strcmp(key, "gsm.version.baseband") || !strcmp(key, "ro.boot.baseband") ||
        !strcmp(key, "ro.baseband")) {
        return get("baseband");
    }
    if (!strcmp(key, "ro.build.description")) {
        std::string desc = get("description");
        if (!desc.empty()) return desc;
        std::string prod = get("name");
        if (prod.empty()) prod = get("product");
        if (prod.empty()) prod = get("device");
        std::string rel = get("release");
        if (rel.empty()) rel = "13";
        std::string bid = get("buildid");
        if (bid.empty()) bid = get("id");
        std::string inc = get("incremental");
        if (!prod.empty() && !bid.empty()) {
            return prod + "-user " + rel + " " + bid + " " + inc + " release-keys";
        }
    }

    if ((getuid() / AID_APP_START) >= 1) {   // hide ADB/debug state and spoof crypto for apps only
        if (!strcmp(key, "ro.crypto.state")) return std::string("encrypted");
        if (!strcmp(key, "ro.crypto.type"))  return std::string("file");
        if (!strcmp(key, "vold.decrypt"))    return std::string("0");
        if (!strcmp(key, "ro.adb.secure"))   return std::string("1");
        if (!strcmp(key, "sys.usb.state") || !strcmp(key, "sys.usb.config") ||
            !strcmp(key, "persist.sys.usb.config")) return std::string("mtp");
        if (!strcmp(key, "init.svc.adbd")) return std::string("stopped");
        if (!strcmp(key, "persist.service.adb.enable")) return std::string("0");
    }

    // SIM & Roaming properties
    if (!strcmp(key, "gsm.sim.state")) {
        std::string s = get("sim_state");
        return s.empty() ? std::string("LOADED") : s;
    }
    if (!strcmp(key, "gsm.operator.isroaming")) {
        return std::string("false");
    }

    // Universal Partition-Specific Identity Matcher
    if (!strncmp(key, "ro.product.", 11)) {
        const char* dot = strrchr(key, '.');
        if (dot) {
            if (!strcmp(dot, ".model")) return get("model");
            if (!strcmp(dot, ".brand")) return get("brand");
            if (!strcmp(dot, ".manufacturer")) {
                std::string m = get("manufacturer");
                return m.empty() ? get("brand") : m;
            }
            if (!strcmp(dot, ".device")) return get("device");
            if (!strcmp(dot, ".name")) return get("name");
        }
    }

    if (strstr(key, ".build.fingerprint")) return get("fingerprint");
    if (strstr(key, ".build.id")) return get("buildid");
    if (strstr(key, ".build.display.id")) return get("displayid");
    if (strstr(key, ".build.version.incremental")) return get("incremental");
    if (strstr(key, ".build.version.security_patch")) return get("securitypatch");

    if (!strcmp(key, "ro.bootloader") || !strcmp(key, "ro.boot.bootloader")) {
        std::string b = get("bootloader");
        if (!b.empty()) return b;
        b = get("incremental");
        if (!b.empty()) return b;
        return get("buildid");
    }

    for (const auto& p : kPropMap)
        if (!strcmp(key, p.prop)) return get(p.field);
    return {};
}

std::string filterGlExtensions(const char* rawExtensions) {
    if (!rawExtensions) return "";

    // 1. Authoritative: check custom extensions file configured in profile
    std::string custom = get("GLExtensions");
    if (custom.empty()) custom = get("gl_extensions");
    if (!custom.empty()) return custom;

    // 2. Check spoofed GPU vendor and renderer
    std::string targetVendor = get("GLVendor");
    std::string targetRender = get("GLRender");

    // Nếu không có profile hoặc profile đích là ARM/Mali: Giữ nguyên 100% extensions thật
    if ((targetVendor.empty() && targetRender.empty()) ||
        (targetVendor.find("ARM") != std::string::npos) ||
        (targetRender.find("Mali") != std::string::npos)) {
        return std::string(rawExtensions);
    }

    // Nếu profile đích là Qualcomm (Adreno) hoặc khác: Lọc bỏ toàn bộ token GL_MALI_* và GL_ARM_*
    std::istringstream stream(rawExtensions);
    std::string token;
    std::string result;

    while (stream >> token) {
        if (token.rfind("GL_MALI_", 0) == 0 || token.rfind("GL_ARM_", 0) == 0) {
            continue; // Bỏ qua extension đặc thù của Mali để không bị lộ
        }
        if (!result.empty()) {
            result += " ";
        }
        result += token;
    }

    return result;
}

static pid_t s_last_pid = 0;
static long long s_cached_offset = -1;
long long uptimeOffsetMs() {
    // Chỉ áp dụng cho app người dùng (UID >= 10000), giữ nguyên cho system_server
    if ((getuid() / AID_APP_START) < 1) return 0;
    pid_t current_pid = getpid();
    if (s_last_pid != current_pid) {
        s_last_pid = current_pid;
        s_cached_offset = -1; // reset cache khi process mới fork
    }
    if (s_cached_offset < 0) {
        std::string v = get("realtime");
        if (v.empty()) v = get("uptime");
        if (!v.empty()) {
            long long ms = strtoll(v.c_str(), nullptr, 10);
            s_cached_offset = (ms < 0) ? 0 : ms;
        } else {
            s_cached_offset = 0;
        }
    }
    return s_cached_offset;
}

}  // namespace hwcfg
