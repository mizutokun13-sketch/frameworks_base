// hwcfg.h — LogaRom hardware-identity spoof engine (reconstructed from
// libandroid_runtime_patched.so). Compiled INTO libandroid_runtime.so.
//
// Activation: returns real values unless /data/vendor/hwcfg/seed exists and
// base64-decodes to >= 32 bytes. All values are decrypted from /system/Utils/<field>.
#pragma once
#include <string>

namespace hwcfg {

// True if the seed is present and the AES key derived OK (engine active).
bool enabled();

// Decrypt and return /system/Utils/<name>. Empty string if absent/disabled/fail.
// Result cached per-process. name is also the GCM AAD.
std::string get(const char* name);

// Map a system property key to a spoofed value (see prop_map.json / kPropMap).
// Returns "" if the key is not spoofed (caller then uses the real property).
std::string lookupProp(const char* key);

// Given the driver's real GL_EXTENSIONS string, return the version to expose:
// unchanged when spoofing to an ARM/Mali GPU, else with all GL_MALI_* removed.
std::string filterGlExtensions(const char* realExtensions);

// Milliseconds to add to elapsedRealtime for app processes. 0 if unset.
long long uptimeOffsetMs();

}  // namespace hwcfg
