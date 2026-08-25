// Multi-source profile support: /data/vendor/hwcfg/active/Utils/ -> /data/local/tmp/Utils/ -> /system/Utils/
// Dynamic reload via gsm.hwcfg.reload property change.

#include "hwcfg.h"

#include <cutils/properties.h>
#include <unistd.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <mutex>
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

// Activation: the flag file exists or fallback to system utils or app UID >= 10000.
bool is_enabled() {
    int pid = getpid();
    if (g_pid != pid) { g_pid = pid; g_state = 0; g_cache.clear(); }  // re-check per fork
    if (g_state) return g_state == 1;

    // 0. System processes (system_server, com.android.systemui, etc.) must NEVER be spoofed
    if (getuid() < AID_APP_START && getuid() != 0) {
        g_state = 2; // disabled
        return false;
    }

    // 1. Always enabled for 3rd party apps
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
        flag = readFile("/data/local/tmp/hwcfg_enabled");
    }
    if (flag.empty()) {
        FILE* f = fopen("/system/Utils/IMEI", "rb");
        if (f) {
            fclose(f);
            flag = "1";
        }
    }
    if (flag.empty()) {
        FILE* f = fopen("/data/local/tmp/Utils/IMEI", "rb");
        if (f) {
            fclose(f);
            flag = "1";
        }
    }
    // trim so a file of only whitespace counts as empty/off
    size_t e = flag.find_last_not_of(" \t\r\n");
    g_state = (e == std::string::npos) ? -1 : 1;
    return g_state == 1;
}

struct PropPair { const char* prop; const char* field; };
// Property map mapping system properties to spoofed Utils keys
static const PropPair kPropMap[] = {
    {"gsm.hwcfg.imei","IMEI"},{"gsm.hwcfg.meid","Meid"},{"gsm.hwcfg.imsi","SubscriberId"},
    {"gsm.hwcfg.iccid","IccSerialNumber"},{"gsm.hwcfg.operator","SimOperator"},
    {"gsm.hwcfg.opname","SimOperatorName"},{"gsm.hwcfg.line1","PhoneNumber"},
    {"gsm.operator.numeric","SimOperator"},{"gsm.operator.alpha","SimOperatorName"},
    {"gsm.operator.iso-country","CountryCode"},
    {"gsm.sim.operator.numeric","SimOperator"},{"gsm.sim.operator.alpha","SimOperatorName"},
    {"gsm.sim.operator.iso-country","CountryCode"},{"gsm.hwcfg.country","CountryCode"},
    {"persist.sys.country","CountryCode"},{"wlan.hwcfg.mac","wifiMac"},
    {"wlan.hwcfg.ssid","wifiName"},{"wlan.hwcfg.bssid","BSSID"},
    {"ro.serialno","SerialNo"},{"ro.boot.serialno","SerialNo"},
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
    {"ro.board.platform","platform"},{"ro.hardware","platform"},{"ro.boot.hardware","platform"},
    {"ro.hardware.chipname","platform"},{"ro.soc.model","socmodel"},
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
    {"ro.modversion","displayid"},{"gsm.hwcfg.lat","lat"},{"gsm.hwcfg.lon","lon"},
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
    return nullptr;
}

}  // namespace

bool enabled() {
    std::lock_guard<std::mutex> lk(g_lock);
    return is_enabled();
}

std::string get(const char* name) {
    if (!name || !*name) return {};
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

    // 1. Check System Properties: sys.hwcfg.<name> and persist.sys.hwcfg.<name>
    char prop_val[PROPERTY_VALUE_MAX] = {0};
    std::string prop_key = "sys.hwcfg.";
    prop_key += name;
    property_get(prop_key.c_str(), prop_val, "");
    if (prop_val[0] == 0) {
        prop_key = "persist.sys.hwcfg.";
        prop_key += name;
        property_get(prop_key.c_str(), prop_val, "");
    }
    if (prop_val[0] != 0) {
        g_cache[name] = prop_val;
        return prop_val;
    }

    // 2. Check File Precedence (SELinux-allowed vendor directories first):
    // 1. /data/vendor/hwcfg/Utils/
    // 2. /data/vendor/hwcfg/active/Utils/
    // 3. /data/data/com.wantphone.wantspoof/files/Utils/
    // 4. /data/local/tmp/Utils/
    // 5. /system/Utils/
    // 6. /sdcard/WantSpoof/Utils/
    std::string path = "/data/vendor/hwcfg/Utils/";
    path += name;
    std::string v = readFile(path.c_str());

    if (v.empty()) {
        path = "/data/vendor/hwcfg/active/Utils/";
        path += name;
        v = readFile(path.c_str());
    }

    if (v.empty()) {
        path = "/data/data/com.wantphone.wantspoof/files/Utils/";
        path += name;
        v = readFile(path.c_str());
    }

    if (v.empty()) {
        path = "/data/local/tmp/Utils/";
        path += name;
        v = readFile(path.c_str());
    }

    if (v.empty()) {
        path = "/system/Utils/";
        path += name;
        v = readFile(path.c_str());
    }

    if (v.empty()) {
        path = "/sdcard/WantSpoof/Utils/";
        path += name;
        v = readFile(path.c_str());
    }

    if (v.empty()) {
        path = "/storage/emulated/0/WantSpoof/Utils/";
        path += name;
        v = readFile(path.c_str());
    }

    if (v.empty()) {
        if (const char* alias = aliasField(name)) {
            const char* dirs[] = {"/data/vendor/hwcfg/Utils/", "/data/vendor/hwcfg/active/Utils/",
                                  "/data/data/com.wantphone.wantspoof/files/Utils/",
                                  "/data/local/tmp/Utils/", "/system/Utils/",
                                  "/sdcard/WantSpoof/Utils/",
                                  "/storage/emulated/0/WantSpoof/Utils/"};
            for (const char* dir : dirs) {
                path = dir;
                path += alias;
                v = readFile(path.c_str());
                if (!v.empty()) break;
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

    if (!strcmp(key, "ro.debuggable"))   return enabled() ? std::string("0") : std::string();
    if (!strcmp(key, "ro.secure"))       return enabled() ? std::string("1") : std::string();
    if (!strcmp(key, "ro.build.type"))   return enabled() ? std::string("user") : std::string();
    if (!strcmp(key, "ro.build.tags"))   return enabled() ? std::string("release-keys") : std::string();

    if (!enabled()) return {};

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
    if (!strcmp(key, "ro.boot.warranty_bit") || !strcmp(key, "ro.warranty_bit")) return std::string("0");
    if (!strcmp(key, "ro.boot.selinux")) return std::string("enforcing");
    if (!strcmp(key, "ro.serialno") || !strcmp(key, "ro.boot.serialno")) {
        std::string s = get("SerialNo");
        return s.empty() ? get("serial") : s;
    }

    if (!strcmp(key, "ro.product.board")) {
        std::string b = get("board");
        return b.empty() ? get("device") : b;
    }
    if (!strcmp(key, "ro.board.platform") || !strcmp(key, "ro.hardware") ||
        !strcmp(key, "ro.boot.hardware") || !strcmp(key, "ro.hardware.chipname")) {
        std::string p = get("platform");
        if (!p.empty()) return p;
        p = get("hardware");
        if (!p.empty()) return p;
        p = get("board");
        if (!p.empty()) return p;
        return get("socmodel");
    }

    if (!strcmp(key, "ro.build.id") || !strcmp(key, "ro.system.build.id") ||
        !strcmp(key, "ro.vendor.build.id") || !strcmp(key, "ro.odm.build.id")) {
        std::string bid = get("buildid");
        return bid.empty() ? get("id") : bid;
    }
    if (!strcmp(key, "ro.build.display.id") || !strcmp(key, "ro.derp.version") ||
        !strcmp(key, "ro.modversion")) {
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

    for (const auto& p : kPropMap)
        if (!strcmp(key, p.prop)) return get(p.field);
    return {};
}

std::string filterGlExtensions(const char* real) {
    if (!real || !*real) return {};
    std::string vendor   = get("GLVendor");
    std::string renderer = get("GLRender");
    bool mali = vendor.find("ARM") != std::string::npos &&
                renderer.find("Mali") != std::string::npos;
    if (mali) return real;

    std::string out;
    const char* p = real;
    while (*p) {
        while (*p == ' ') ++p;
        const char* start = p;
        while (*p && *p != ' ') ++p;
        std::string tok(start, p - start);
        if (tok.empty()) continue;
        if (tok.rfind("GL_MALI_", 0) == 0) continue;
        if (!out.empty()) out += ' ';
        out += tok;
    }
    return out;
}

long long uptimeOffsetMs() {
    if ((getuid() / AID_APP_START) < 1) return 0;
    std::string v = get("realtime");
    if (v.empty()) return 0;
    long long ms = strtoll(v.c_str(), nullptr, 10);
    return ms < 0 ? 0 : ms;
}

}  // namespace hwcfg
