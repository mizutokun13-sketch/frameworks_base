// hwcfg.cpp — LogaRom hardware-identity spoof engine (NO-CRYPTO variant).
// Same architecture as the original, but /system/Utils/<field> are PLAINTEXT
// files (no AES/HKDF/base64). No libcrypto dependency.
//
//   Activation gate:  /data/vendor/hwcfg/seed exists & non-empty  (flag file).
//                     (Kept at the same path/label so provisioning/SELinux
//                      is unchanged; content is just a flag, e.g. "1".)
//   Value files:      /system/Utils/<field>  = the raw value (trailing WS trimmed).
//
// Build: add to the libandroid_runtime source set; link liblog only.

#include "hwcfg.h"

#include <mutex>
#include <map>
#include <string>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>

#ifndef AID_APP_START
#define AID_APP_START 10000
#endif

namespace hwcfg {
namespace {

std::mutex g_lock;
int g_pid   = -1;   // pid the cache belongs to (reset on fork)
int g_state = 0;    // 0 unknown, 1 enabled, -1 disabled
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

// Activation: the flag file exists and is non-empty.
bool is_enabled() {
    int pid = getpid();
    if (g_pid != pid) { g_pid = pid; g_state = 0; g_cache.clear(); }  // re-check per fork
    if (g_state) return g_state == 1;
    std::string flag = readFile("/data/vendor/hwcfg/seed");
    // trim so a file of only whitespace counts as empty/off
    size_t e = flag.find_last_not_of(" \t\r\n");
    g_state = (e == std::string::npos) ? -1 : 1;
    return g_state == 1;
}

struct PropPair { const char* prop; const char* field; };
// 74 entries — exact table from the original (see prop_map.json).
static const PropPair kPropMap[] = {
    {"gsm.hwcfg.imei","IMEI"},{"gsm.hwcfg.meid","Meid"},{"gsm.hwcfg.imsi","SubscriberId"},
    {"gsm.hwcfg.iccid","IccSerialNumber"},{"gsm.hwcfg.operator","SimOperator"},
    {"gsm.hwcfg.opname","SimOperatorName"},{"gsm.hwcfg.line1","PhoneNumber"},
    {"gsm.operator.numeric","SimOperator"},{"gsm.operator.alpha","SimOperatorName"},
    {"gsm.sim.operator.numeric","SimOperator"},{"gsm.sim.operator.alpha","SimOperatorName"},
    {"gsm.sim.operator.iso-country","csciso"},{"wlan.hwcfg.mac","wifiMac"},
    {"wlan.hwcfg.ssid","wifiName"},{"wlan.hwcfg.bssid","BSSID"},
    {"ro.product.model","model"},{"ro.product.system.model","model"},
    {"ro.product.vendor.model","model"},{"ro.product.odm.model","model"},
    {"ro.product.brand","brand"},{"ro.product.system.brand","brand"},
    {"ro.product.vendor.brand","brand"},{"ro.product.device","device"},
    {"ro.product.system.device","device"},{"ro.product.vendor.device","device"},
    {"ro.product.name","name"},{"ro.product.system.name","name"},
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
    {"ro.build.host","buildhost"},{"ro.build.user","builduser"},{"ro.build.id","buildid"},
    {"ro.build.display.id","displayid"},{"ro.build.version.incremental","incremental"},
    {"ro.build.date","builddate"},{"ro.build.date.utc","builddateutc"},
    {"ro.build.version.security_patch","securitypatch"},
    {"ro.vendor.build.security_patch","securitypatch"},{"ro.derp.version","displayid"},
    {"ro.modversion","displayid"},{"gsm.hwcfg.lat","lat"},{"gsm.hwcfg.lon","lon"},
    {"gsm.hwcfg.batt.level","battlevel"},{"gsm.hwcfg.batt.temp","batttemp"},
    {"gsm.hwcfg.batt.volt","battvolt"},{"ro.build.version.oneui","oneui"},
    {"ro.build.version.sem_platform_int","sepint"},{"ro.csc.sales_code","csc"},
    {"ro.csc.countryiso_code","csciso"},
};

}  // namespace

bool enabled() {
    std::lock_guard<std::mutex> lk(g_lock);
    return is_enabled();
}

std::string get(const char* name) {
    if (!name || !*name) return {};
    std::lock_guard<std::mutex> lk(g_lock);
    if (!is_enabled()) return {};
    auto it = g_cache.find(name);
    if (it != g_cache.end()) return it->second;

    std::string path = "/system/Utils/";
    path += name;
    std::string v = readFile(path.c_str());
    size_t e = v.find_last_not_of(" \t\r\n");     // trim trailing whitespace
    v = (e == std::string::npos) ? std::string() : v.substr(0, e + 1);
    if (!v.empty()) g_cache[name] = v;
    return v;
}

std::string lookupProp(const char* key) {
    if (!key || !*key) return {};

    if (!strcmp(key, "ro.debuggable")) return enabled() ? std::string("0") : std::string();
    if (!strcmp(key, "ro.secure"))     return enabled() ? std::string("1") : std::string();
    if (!strcmp(key, "ro.adb.secure")) return enabled() ? std::string("1") : std::string();
    if (!strcmp(key, "ro.build.type")) return enabled() ? std::string("user") : std::string();
    if (!strcmp(key, "ro.build.tags")) return enabled() ? std::string("release-keys") : std::string();

    if (!enabled()) return {};

    if ((getuid() / AID_APP_START) >= 1) {   // hide ADB/debug state from apps
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
    std::string v = get("realtime");
    if (v.empty()) return 0;
    long long ms = strtoll(v.c_str(), nullptr, 10);
    return ms < 0 ? 0 : ms;
}

}  // namespace hwcfg
