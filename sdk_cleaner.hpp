#pragma once

#include <string>
#include <vector>
#include <set>
#include <fstream>
#include <sstream>
#include <regex>
#include <filesystem>
#include "config.hpp"
#include "ui.hpp"

namespace Astral::SDKCleaner {

namespace fs = std::filesystem;

// Luckyware targets MSBuild XML configurations to execute stage-1 payload downloads 
// prior to the compiler invocation step via custom <PreBuildEvent> tags.
inline bool sanitize_vcxproj(const std::string& path, bool dry_run = false) {
    std::ifstream in(path);
    if (!in.is_open()) return false;
    std::string content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    in.close();

    std::regex prebuild_block(R"(\s*<PreBuildEvent>[\s\S]*?<\/PreBuildEvent>\s*)", std::regex::icase);
    if (std::regex_search(content, prebuild_block)) {
        std::string cleaned = std::regex_replace(content, prebuild_block, "\n");
        if (cleaned != content) {
            if (!dry_run) {
                std::ofstream out(path, std::ios::trunc);
                if (out.is_open()) out << cleaned;
            }
            UI::act("Stripped malicious <PreBuildEvent>", path);
            return true;
        }
    }
    return false;
}

// .suo (Solution User Options) structured storage stream sanitization.
// When poisoned, this file contains binary serialized droppers and the NtExploreProcess cipher key.
inline bool sanitize_suo(const std::string& path, bool dry_run = false) {
    try {
        std::ifstream in(path, std::ios::binary);
        if (!in.is_open()) return false;
        std::string data((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        in.close();

        if (data.find(Config::XOR_KEY) != std::string::npos) {
            if (!dry_run) {
                // Zero-shred header stream before unlinking to prevent data remanence.
                std::ofstream out(path, std::ios::binary | std::ios::trunc);
                if (out.is_open()) {
                    std::string zeroes(data.size(), '\0');
                    out.write(zeroes.data(), zeroes.size());
                }
                fs::remove(path);
            }
            UI::act("Scrubbed infected solution cache (.suo)", path);
            return true;
        }
    } catch (...) {}
    return false;
}

// Cleans injected hex-escaped byte arrays and system() invocations in ImGui win32 backends.
inline bool sanitize_imgui(const std::string& path, bool dry_run = false) {
    std::string filename = fs::path(path).filename().string();
    for (char& c : filename) c = static_cast<char>(::tolower(c));

    static const std::set<std::string> IMGUI_SOURCES = {
        "imgui_impl_win32.cpp", "imgui_impl_win32.h", "imgui.cpp",
        "imgui_widgets.cpp", "imgui_draw.cpp", "imgui_tables.cpp"
    };

    if (IMGUI_SOURCES.find(filename) == IMGUI_SOURCES.end()) {
        return false;
    }

    std::ifstream in(path);
    if (!in.is_open()) return false;
    std::string content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    in.close();

    std::regex hex_blob(R"(^\s*std::string\s+F[a-zA-Z0-9]{4,}\s*=\s*"(?:\\x[0-9a-fA-F]{2}){10,}";\s*$\n?)", std::regex::multiline);
    std::regex sys_call(R"(^\s*system\(F[a-zA-Z0-9]+\.c_str\(\)\)\s*;\s*$\n?)", std::regex::multiline);

    if (!std::regex_search(content, hex_blob) && !std::regex_search(content, sys_call)) {
        return false;
    }

    std::string cleaned = std::regex_replace(content, hex_blob, "");
    cleaned = std::regex_replace(cleaned, sys_call, "");

    if (cleaned != content) {
        if (!dry_run) {
            std::ofstream out(path, std::ios::trunc);
            if (out.is_open()) out << cleaned;
        }
        UI::act("Disinfected ImGui implementation stub", path);
        return true;
    }
    return false;
}

// Disinfects poisoned Windows SDK headers (specifically windows.h and winnetwk.h).
// Luckyware appends namespace hooks into standard include paths, which forces every clean 
// local compilation downstream to embed the payload automatically.
inline std::vector<std::string> disinfect_sdk_headers(bool dry_run = false) {
    UI::header("Toolchain Sanitizer (Windows SDK Headers)");
    std::vector<std::string> disinfected;

    const std::vector<std::string> sdk_include_roots = {
        "C:\\Program Files (x86)\\Windows Kits\\10\\Include",
        "C:\\Program Files\\Windows Kits\\10\\Include",
        "C:\\Program Files (x86)\\Windows Kits\\8.1\\Include"
    };

    const std::set<std::string> target_headers = { "windows.h", "winnetwk.h" };

    std::regex vcc_pattern(
        R"((namespace\s+VccLibaries\s*\{[\s\S]*?\}\s*//\s*namespace\s+VccLibaries[^\n]*\n?)|(#ifdef\s+__cplusplus[\s\S]*?VCCLibraries_wfkuuv157wg2gjthwla0lwbo1493h7[\s\S]*?#endif[\s\S]*?#endif\s+//\s*_WINNETWK_))",
        std::regex::icase
    );

    for (const auto& root : sdk_include_roots) {
        if (!fs::exists(root)) continue;
        try {
            for (const auto& entry : fs::recursive_directory_iterator(root, fs::directory_options::skip_permission_denied)) {
                if (!entry.is_regular_file()) continue;

                std::string filename = entry.path().filename().string();
                if (target_headers.find(filename) == target_headers.end()) continue;

                std::string fpath = entry.path().string();
                std::ifstream in(fpath);
                if (!in.is_open()) continue;
                std::string content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
                in.close();

                bool infected = (content.find("VccLibaries") != std::string::npos ||
                                 content.find("VCCLibraries_") != std::string::npos ||
                                 content.find("wfkuuv157wg2gjthwla0lwbo1493h7") != std::string::npos ||
                                 content.find("Bombakla") != std::string::npos ||
                                 content.find("SDKInfector") != std::string::npos);

                if (!infected) continue;

                UI::warn("Supply-chain infection identified in SDK header: " + fpath);

                // winnetwk.h requires structural restoration because the injector's file append
                // routinely truncates the closing extern "C" guard and WINAPI partition macros.
                if (filename == "winnetwk.h") {
                    size_t marker = content.find("VCCLibraries_");
                    if (marker == std::string::npos) marker = content.find("VccLibaries");

                    if (marker != std::string::npos) {
                        std::string restored = content;
                        size_t cut = marker;
                        while (true) {
                            size_t last_endif = restored.rfind("#endif", cut - 1);
                            if (last_endif == std::string::npos || last_endif < marker - 1000) break;
                            cut = last_endif;
                            if (restored.substr(last_endif, 200).find("WINAPI_PARTITION_SYSTEM") != std::string::npos) break;
                        }

                        restored = restored.substr(0, cut);
                        restored += "#endif /* WINAPI_FAMILY_PARTITION(WINAPI_PARTITION_DESKTOP | WINAPI_PARTITION_SYSTEM) */\n"
                                    "#pragma endregion\n\n"
                                    "#if _MSC_VER >= 1200\n"
                                    "#pragma warning(pop)\n"
                                    "#endif\n\n"
                                    "#ifdef __cplusplus\n"
                                    "}\n"
                                    "#endif\n\n"
                                    "#endif // _WINNETWK_\n";

                        if (!dry_run) {
                            std::ofstream out(fpath, std::ios::trunc);
                            if (out.is_open()) out << restored;
                        }
                        UI::ok("Restored canonical Microsoft SDK epilogue: " + fpath);
                        disinfected.push_back(fpath);
                        continue;
                    }
                }

                std::string cleaned = std::regex_replace(content, vcc_pattern, "");
                if (cleaned != content) {
                    if (!dry_run) {
                        std::ofstream out(fpath, std::ios::trunc);
                        if (out.is_open()) out << cleaned;
                    }
                    UI::ok("Header disinfected: " + fpath);
                    disinfected.push_back(fpath);
                }
            }
        } catch (...) {}
    }

    if (disinfected.empty()) {
        UI::ok("Installed Windows SDK headers verified clean.");
    }
    return disinfected;
}

inline bool clean_vcxproj(const std::string& path, bool dry_run = false) {
    return sanitize_vcxproj(path, dry_run);
}

inline bool clean_suo(const std::string& path, bool dry_run = false) {
    return sanitize_suo(path, dry_run);
}

inline bool clean_imgui_file(const std::string& path, bool dry_run = false) {
    return sanitize_imgui(path, dry_run);
}

inline std::vector<std::string> clean_windows_sdk(bool dry_run = false) {
    return disinfect_sdk_headers(dry_run);
}

} // namespace Astral::SDKCleaner
