#pragma once

#include <string>
#include <string_view>
#include <vector>
#include <set>
#include <regex>

namespace Astral::Config {

inline constexpr std::string_view APP_NAME    = "Astral";
inline constexpr std::string_view APP_VERSION = "3.2.0";
inline constexpr std::string_view AUTHOR      = "ion (@ionj)";

// Primary C2 infrastructure observed across Luckyware/Darkside campaigns.
inline const std::vector<std::string> C2_DOMAINS = {
    "exo-api.tf", "api.exo-api.tf", "gate.exo-api.tf", "c2.exo-api.tf",
    "exoapi.xyz", "exoapi.cc", "exoapi.top", "exoapi.online",
    "exo-api.online", "exo-api.cc", "exo-api.xyz",
    "devruntime.cy", "api.devruntime.cy", "cdn.devruntime.cy", "auth.devruntime.cy", "gate.devruntime.cy",
    "dhszo.darkside.cy", "darkside.cy",
    "zetolacs-cloud.top", "frozi.cc", "concodro.lat", "krispykreme.top", "krispykreme.pw",
    "wallmart.mom", "stratum.ravenminer.com", "matchashop.icu",
    "vcc-library.online", "vcc-library.help", "vcc-library.uk",
    "vcc-redistrbutable.help", "vcc-redistrbutable.top",
    "i-slept-with-ur.mom", "i-like.boats", "nuzzyservices.com",
    "balista.lol", "phobos.top", "phobosransom.com", "pee-files.nl",
    "luckyware.co", "luckyware.cc", "luckyware.pw", "luckyware.queenmc.pl",
    "risesmp.net", "luckystrike.pw", "powercat.dog"
};

inline const std::vector<std::string> C2_IPS = {
    "91.92.243.218",
    "188.114.96.11"
};

// Known payload binaries dropped by the stage-1 loaders.
inline const std::vector<std::string> MALWARE_BINARIES = {
    "berok.exe", "hpsr.exe", "zetolac.exe", "retev.exe",
    "berok64.exe", "hpsr64.exe", "pedoclown666.jpeg", "twerkmaster69.jpeg"
};

inline const std::vector<std::string> STAGED_ARTIFACTS = {
    "Berok.exe", "HPSR.exe", "Zetolac.exe", "Retev.exe",
    "PedoClown666.jpeg", "TwerkMaster69.jpeg",
    "ntos", "wkkr.bug", "bungee.boo", "ntb.dat",
    "chc11", "cps11", "eck11", "eps11", "bccb11", "bppb11"
};

// Hardcoded XOR encryption key used in payload stubs.
inline constexpr std::string_view XOR_KEY = "NtExploreProcess";

inline const std::vector<std::string> SIGNATURES = {
    "NtExploreProcess",
    "VccLibaries",
    "VCCLibraries_",
    "VccFramework",
    "PFLwrx",
    "SDKInfector",
    "Bombakla",
    "Rundollay",
    "InfectSDK",
    "InfectINIT",
    "wfkuuv157wg2gjthwla0lwbo1493h7"
};

inline constexpr std::string_view HOSTS_TAG_START = "# ASTRAL NETWORK SHIELD START";
inline constexpr std::string_view HOSTS_TAG_END   = "# ASTRAL NETWORK SHIELD END";

// Stage-1 temp files generated using std::chrono::system_clock milliseconds: [A-Z]{2,3}[0-9]{10,13}
inline const std::regex CHRONO_DROPPERS_REGEX(R"(^[A-Za-z]{2,3}\d{10,13}(\.exe)?$)", std::regex::icase);

// Regex targeting active Discord exfiltration webhooks.
inline const std::regex DISCORD_WEBHOOK_REGEX(
    R"(https?://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d{17,20}/[\w-]{60,80})",
    std::regex::icase
);

inline const std::set<std::string> SCAN_EXTENSIONS = {
    ".exe", ".dll", ".vcxproj", ".suo", ".cpp", ".hpp", ".h",
    ".ps1", ".vbs", ".bat", ".cmd", ".js"
};

} // namespace Astral::Config
