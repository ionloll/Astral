#pragma once

#include <windows.h>
#include <shlobj.h>
#include <string>
#include <vector>
#include <regex>
#include <filesystem>
#include <fstream>
#include <algorithm>
#include "config.hpp"
#include "pe_patcher.hpp"
#include "ui.hpp"

namespace Astral::PersistenceHunter {

namespace fs = std::filesystem;

inline std::string get_env_var(const std::string& var) {
    char* buf = nullptr;
    size_t len = 0;
    if (_dupenv_s(&buf, &len, var.c_str()) == 0 && buf != nullptr) {
        std::string res(buf);
        free(buf);
        return res;
    }
    return "";
}

// Inspects standard Windows user and machine Run/RunOnce keys for malware startup commands.
inline int clean_registry_persistence(bool dry_run = false) {
    UI::section_header("Persistence Audit - Registry Run Keys");
    int deleted = 0;

    struct HiveTarget {
        HKEY root;
        std::string subkey;
    };

    const std::vector<HiveTarget> targets = {
        { HKEY_CURRENT_USER,  "Software\\Microsoft\\Windows\\CurrentVersion\\Run" },
        { HKEY_CURRENT_USER,  "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" },
        { HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" },
        { HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce" },
        { HKEY_LOCAL_MACHINE, "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run" },
        { HKEY_CURRENT_USER,  "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run" },
        { HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run" }
    };

    static const std::regex pattern(
        R"((i-like\.boats|krispykreme|nuzzyservices|devruntime\.cy|luckyware|exo-api|berok\.exe|zetolac\.exe|powershell.*hidden|iwr.*-uri|VccFramework|PFLwrx|CDat\.bin))",
        std::regex::icase
    );

    for (const auto& t : targets) {
        HKEY hkey = nullptr;
        if (RegOpenKeyExA(t.root, t.subkey.c_str(), 0, KEY_READ | KEY_SET_VALUE, &hkey) != ERROR_SUCCESS) {
            continue;
        }

        std::vector<std::string> prune_list;
        DWORD index = 0;
        char val_name[256] = {};
        BYTE val_data[4096] = {};

        while (true) {
            DWORD name_len = sizeof(val_name);
            DWORD data_len = sizeof(val_data);
            DWORD type = 0;

            if (RegEnumValueA(hkey, index++, val_name, &name_len, nullptr, &type, val_data, &data_len) != ERROR_SUCCESS) {
                break;
            }

            const std::string val_str(reinterpret_cast<char*>(val_data), data_len);
            if (std::regex_search(val_str, pattern)) {
                UI::log_threat("Malicious registry value: [" + t.subkey + "] " + val_name + " -> " + val_str.substr(0, 60));
                prune_list.push_back(val_name);
            }
            std::memset(val_name, 0, sizeof(val_name));
            std::memset(val_data, 0, sizeof(val_data));
        }

        for (const auto& val : prune_list) {
            if (!dry_run) {
                if (RegDeleteValueA(hkey, val.c_str()) == ERROR_SUCCESS) {
                    UI::log_action("Deleted registry persistence value: " + val);
                    deleted++;
                }
            } else {
                deleted++;
            }
        }
        RegCloseKey(hkey);
    }

    if (deleted == 0) {
        UI::log_success("Registry Run hives verified clean.");
    }
    return deleted;
}

// Scans current and all-users Startup folders for dropped payload executables and shortcuts.
inline int scan_startup_folders(bool dry_run = false) {
    int removed = 0;
    std::vector<std::string> startup_dirs;

    char user_startup[MAX_PATH] = {};
    SHGetFolderPathA(nullptr, CSIDL_STARTUP, nullptr, 0, user_startup);
    if (user_startup[0] != '\0') startup_dirs.push_back(user_startup);

    char common_startup[MAX_PATH] = {};
    SHGetFolderPathA(nullptr, CSIDL_COMMON_STARTUP, nullptr, 0, common_startup);
    if (common_startup[0] != '\0') startup_dirs.push_back(common_startup);

    for (const auto& dir : startup_dirs) {
        if (!fs::exists(dir)) continue;
        try {
            for (const auto& entry : fs::directory_iterator(dir)) {
                if (!entry.is_regular_file()) continue;
                std::string fname = entry.path().filename().string();
                std::string lower_fname = fname;
                std::transform(lower_fname.begin(), lower_fname.end(), lower_fname.begin(), ::tolower);

                bool is_bad = false;
                for (const auto& target : Config::MALWARE_BINARIES) {
                    if (lower_fname == target) {
                        is_bad = true;
                        break;
                    }
                }

                if (is_bad || std::regex_match(fname, Config::CHRONO_DROPPERS_REGEX)) {
                    UI::log_threat("Startup payload detected: " + entry.path().string());
                    if (!dry_run) {
                        PEPatcher::shred_file(entry.path().string());
                    }
                    removed++;
                }
            }
        } catch (...) {}
    }
    return removed;
}

// Disinfects known staging paths (Temp, AppData, ProgramData) and chrono-generated dropper binaries.
inline int purge_staged_payloads(bool dry_run = false) {
    UI::section_header("Persistence Audit - Staged Payloads & Temp Binaries");
    int purged = 0;

    const std::string temp_dir     = get_env_var("TEMP");
    const std::string appdata_dir  = get_env_var("APPDATA");
    const std::string localapp_dir = get_env_var("LOCALAPPDATA");
    const std::string progdata_dir = get_env_var("PROGRAMDATA");

    const std::vector<std::string> search_bases = { temp_dir, appdata_dir, localapp_dir, progdata_dir };

    for (const auto& base : search_bases) {
        if (base.empty() || !fs::exists(base)) continue;
        for (const auto& filename : Config::STAGED_ARTIFACTS) {
            const std::string target_path = base + "\\" + filename;
            if (fs::exists(target_path)) {
                UI::log_threat("Identified dropped payload artifact: " + target_path);
                if (!dry_run) {
                    PEPatcher::shred_file(target_path);
                    UI::log_action("Purged and shredded: " + target_path);
                }
                purged++;
            }
        }
    }

    // Chrono-named files generated by Stage-1 droppers ([A-Z]{2,3}[0-9]{10,13})
    for (const auto& base : { temp_dir, appdata_dir, localapp_dir }) {
        if (base.empty() || !fs::exists(base)) continue;
        try {
            for (const auto& entry : fs::directory_iterator(base, fs::directory_options::skip_permission_denied)) {
                if (!entry.is_regular_file()) continue;
                const std::string fname = entry.path().filename().string();
                if (std::regex_match(fname, Config::CHRONO_DROPPERS_REGEX)) {
                    UI::log_threat("Chrono-named dropper binary found: " + entry.path().string());
                    if (!dry_run) {
                        PEPatcher::shred_file(entry.path().string());
                        UI::log_action("Purged and shredded: " + entry.path().string());
                    }
                    purged++;
                }
            }
        } catch (...) {}
    }

    if (purged == 0) {
        UI::log_success("No staged droppers or chrono-named binaries identified.");
    }
    return purged;
}

// Removes profapi.dll search-order hijacking payloads and disinfected injected JS loader scripts.
inline int disinfect_discord(bool dry_run = false) {
    UI::section_header("Credential Guard - Discord Injection Remediation");
    int cleaned = 0;

    const std::string localapp = get_env_var("LOCALAPPDATA");
    if (localapp.empty()) return 0;

    const std::vector<std::string> discord_folders = {
        localapp + "\\Discord",
        localapp + "\\DiscordCanary",
        localapp + "\\DiscordPTB"
    };

    for (const auto& dfolder : discord_folders) {
        if (!fs::exists(dfolder)) continue;
        try {
            for (const auto& entry : fs::directory_iterator(dfolder)) {
                if (!entry.is_directory()) continue;
                const std::string folder_name = entry.path().filename().string();
                if (folder_name.rfind("app-", 0) != 0) continue;

                // Hijacked search-order proxy DLL placed in app-* directory
                const std::string profapi = entry.path().string() + "\\profapi.dll";
                if (fs::exists(profapi)) {
                    UI::log_threat("Discord DLL proxy hijack detected: " + profapi);
                    if (!dry_run) {
                        PEPatcher::shred_file(profapi);
                        UI::log_action("Removed proxy DLL: " + profapi);
                    }
                    cleaned++;
                }

                // Injected JavaScript stubs in Electron app package
                const std::string resources_dir = entry.path().string() + "\\resources";
                if (fs::exists(resources_dir)) {
                    for (const auto& rentry : fs::recursive_directory_iterator(resources_dir, fs::directory_options::skip_permission_denied)) {
                        if (!rentry.is_regular_file()) continue;
                        if (rentry.path().extension().string() != ".js") continue;

                        std::ifstream in(rentry.path().string());
                        if (!in.is_open()) continue;
                        const std::string js((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
                        in.close();

                        if (js.find("VccLibaries") != std::string::npos ||
                            js.find("luckyware") != std::string::npos ||
                            js.find("wfkuuv157wg2gjthwla0lwbo1493h7") != std::string::npos) {
                            UI::log_threat("Injected malicious Discord JavaScript hook: " + rentry.path().string());
                            if (!dry_run) {
                                fs::remove(rentry.path());
                                UI::log_action("Removed script hook: " + rentry.path().string());
                            }
                            cleaned++;
                        }
                    }
                }
            }
        } catch (...) {}
    }

    if (cleaned == 0) {
        UI::log_success("Discord installations clean. No DLL proxies or injected JS hooks detected.");
    }
    return cleaned;
}

// Scans text and binary artifacts across directory trees to locate Discord webhook tokens.
inline std::vector<std::pair<std::string, std::string>> hunt_discord_webhooks(const std::string& scan_root) {
    std::vector<std::pair<std::string, std::string>> found;
    if (!fs::exists(scan_root)) return found;

    try {
        for (const auto& entry : fs::recursive_directory_iterator(scan_root, fs::directory_options::skip_permission_denied)) {
            if (!entry.is_regular_file()) continue;
            if (entry.file_size() > 5 * 1024 * 1024) continue;

            std::ifstream in(entry.path().string(), std::ios::binary);
            if (!in.is_open()) continue;
            const std::string content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
            in.close();

            std::smatch match;
            if (std::regex_search(content, match, Config::DISCORD_WEBHOOK_REGEX)) {
                found.push_back({ entry.path().string(), match.str() });
                UI::log_threat("Exfiltration webhook endpoint found in " + entry.path().string() + "\n      └─ URL: " + match.str());
            }
        }
    } catch (...) {}
    return found;
}

// Remediates Edge browser policies abused to establish persistent C2 redirects.
inline int clean_edge_policy_hijacks(bool dry_run = false) {
    int removed = 0;
    const std::string localapp = get_env_var("LOCALAPPDATA");
    if (localapp.empty()) return 0;

    const std::string edge_user_data = localapp + "\\Microsoft\\Edge\\User Data";
    if (!fs::exists(edge_user_data)) return 0;

    static const std::vector<std::string> hijack_folders = { "Domain Actions", "Well Known Domains" };
    for (const auto& f : hijack_folders) {
        const std::string target = edge_user_data + "\\" + f;
        if (fs::exists(target)) {
            UI::log_threat("Edge policy hijack directory detected: " + target);
            if (!dry_run) {
                try {
                    fs::remove_all(target);
                    UI::log_action("Removed hijacked directory: " + target);
                } catch (...) {}
            }
            removed++;
        }
    }
    return removed;
}

} // namespace Astral::PersistenceHunter
