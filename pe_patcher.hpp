#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <fstream>
#include <cstring>
#include <algorithm>
#include <filesystem>
#include "config.hpp"
#include "ui.hpp"

namespace Astral::PEPatcher {

namespace fs = std::filesystem;

struct PEScanResult {
    bool is_pe = false;
    bool is_infected = false;
    bool has_rcd_executable = false;
    bool has_embedded_pe = false;
    bool has_xor_key = false;
    std::string detection_reason;
};

// Overwrites file content with zeroes in 64 KiB chunks before unlinking to prevent recovery.
inline bool shred_file(const std::string& filepath) {
    try {
        if (!fs::exists(filepath)) return false;
        const auto size = fs::file_size(filepath);
        if (size > 0 && size < 100 * 1024 * 1024) {
            std::ofstream out(filepath, std::ios::binary | std::ios::trunc);
            if (out.is_open()) {
                std::vector<char> zeroes(std::min<size_t>(static_cast<size_t>(size), 65536), '\0');
                size_t remaining = static_cast<size_t>(size);
                while (remaining > 0) {
                    const size_t write_sz = std::min(remaining, zeroes.size());
                    out.write(zeroes.data(), write_sz);
                    remaining -= write_sz;
                }
                out.close();
            }
        }
        return fs::remove(filepath);
    } catch (...) {
        return false;
    }
}

// Parses portable executable headers and section tables to detect Luckyware droppers.
inline PEScanResult analyze_pe(const std::string& filepath) {
    PEScanResult res;
    std::ifstream f(filepath, std::ios::binary);
    if (!f.is_open()) return res;

    IMAGE_DOS_HEADER dos_hdr = {};
    f.read(reinterpret_cast<char*>(&dos_hdr), sizeof(dos_hdr));
    if (dos_hdr.e_magic != IMAGE_DOS_SIGNATURE) return res;

    res.is_pe = true;
    f.seekg(dos_hdr.e_lfanew, std::ios::beg);

    DWORD pe_sig = 0;
    f.read(reinterpret_cast<char*>(&pe_sig), sizeof(pe_sig));
    if (pe_sig != IMAGE_NT_SIGNATURE) return res;

    IMAGE_FILE_HEADER file_hdr = {};
    f.read(reinterpret_cast<char*>(&file_hdr), sizeof(file_hdr));
    f.seekg(file_hdr.SizeOfOptionalHeader, std::ios::cur);

    // Scan section headers for appended executable .rcd sections
    for (WORD i = 0; i < file_hdr.NumberOfSections; ++i) {
        IMAGE_SECTION_HEADER sec_hdr = {};
        f.read(reinterpret_cast<char*>(&sec_hdr), sizeof(sec_hdr));

        char sec_name[9] = {};
        std::memcpy(sec_name, sec_hdr.Name, 8);
        std::string name(sec_name);

        if (name.rfind(".rcd", 0) == 0) {
            const bool exec = (sec_hdr.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
            const bool code = (sec_hdr.Characteristics & IMAGE_SCN_CNT_CODE) != 0;
            if (exec || code) {
                res.is_infected = true;
                res.has_rcd_executable = true;
                res.detection_reason = "Malicious executable section detected: " + name;
                break;
            }
        }
    }

    f.seekg(0, std::ios::end);
    const size_t fsize = static_cast<size_t>(f.tellg());
    f.seekg(0, std::ios::beg);

    if (fsize < 30 * 1024 * 1024) {
        std::vector<uint8_t> buffer(fsize);
        f.read(reinterpret_cast<char*>(buffer.data()), fsize);

        // Search for hardcoded XOR key string literal used by Luckyware decryptors
        auto it = std::search(
            buffer.begin(), buffer.end(),
            Config::XOR_KEY.begin(), Config::XOR_KEY.end()
        );
        if (it != buffer.end()) {
            res.is_infected = true;
            res.has_xor_key = true;
            if (res.detection_reason.empty()) {
                res.detection_reason = "Luckyware cipher key (NtExploreProcess) identified in binary";
            }
        }

        // Search for known campaign signatures
        for (const auto& sig : Config::SIGNATURES) {
            auto sit = std::search(buffer.begin(), buffer.end(), sig.begin(), sig.end());
            if (sit != buffer.end()) {
                res.is_infected = true;
                if (res.detection_reason.empty()) {
                    res.detection_reason = "Luckyware campaign signature identified: " + sig;
                }
                break;
            }
        }

        // Structural verification for embedded dropper payloads:
        // Validates nested DOS header and NT PE signature to avoid false positives on random data bytes.
        if (res.has_rcd_executable || res.has_xor_key) {
            for (size_t i = 1024; i + sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS) < buffer.size(); i += 8) {
                if (buffer[i] == 'M' && buffer[i + 1] == 'Z') {
                    const auto* sub_dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(&buffer[i]);
                    if (sub_dos->e_lfanew > 0 && sub_dos->e_lfanew < 0x1000 &&
                        i + static_cast<size_t>(sub_dos->e_lfanew) + 4 <= buffer.size()) {
                        const uint32_t nt_sig = *reinterpret_cast<const uint32_t*>(&buffer[i + sub_dos->e_lfanew]);
                        if (nt_sig == IMAGE_NT_SIGNATURE) {
                            res.has_embedded_pe = true;
                            if (res.detection_reason.empty()) {
                                res.detection_reason = "Nested dropper PE payload structure identified in binary";
                            }
                            break;
                        }
                    }
                }
            }
        }
    }

    f.close();
    return res;
}

// Neutralizes executable payload sections in-place by clearing execution characteristics flags.
inline bool neutralize_pe_section(const std::string& filepath) {
    std::fstream f(filepath, std::ios::binary | std::ios::in | std::ios::out);
    if (!f.is_open()) return false;

    IMAGE_DOS_HEADER dos_hdr = {};
    f.read(reinterpret_cast<char*>(&dos_hdr), sizeof(dos_hdr));
    if (dos_hdr.e_magic != IMAGE_DOS_SIGNATURE) return false;

    f.seekg(dos_hdr.e_lfanew, std::ios::beg);
    DWORD pe_sig = 0;
    f.read(reinterpret_cast<char*>(&pe_sig), sizeof(pe_sig));
    if (pe_sig != IMAGE_NT_SIGNATURE) return false;

    IMAGE_FILE_HEADER file_hdr = {};
    f.read(reinterpret_cast<char*>(&file_hdr), sizeof(file_hdr));
    f.seekg(file_hdr.SizeOfOptionalHeader, std::ios::cur);

    const std::streampos section_start = f.tellg();
    bool patched = false;

    for (WORD i = 0; i < file_hdr.NumberOfSections; ++i) {
        const std::streampos sec_pos = section_start + std::streampos(i * sizeof(IMAGE_SECTION_HEADER));
        f.seekg(sec_pos);

        IMAGE_SECTION_HEADER sec_hdr = {};
        f.read(reinterpret_cast<char*>(&sec_hdr), sizeof(sec_hdr));

        char sec_name[9] = {};
        std::memcpy(sec_name, sec_hdr.Name, 8);
        std::string name(sec_name);

        if (name.rfind(".rcd", 0) == 0) {
            if ((sec_hdr.Characteristics & IMAGE_SCN_MEM_EXECUTE) || (sec_hdr.Characteristics & IMAGE_SCN_CNT_CODE)) {
                sec_hdr.Characteristics &= ~IMAGE_SCN_MEM_EXECUTE;
                sec_hdr.Characteristics &= ~IMAGE_SCN_CNT_CODE;
                f.seekp(sec_pos);
                f.write(reinterpret_cast<char*>(&sec_hdr), sizeof(sec_hdr));
                patched = true;
            }
        }
    }

    f.close();
    if (patched) {
        UI::log_action("Neutralized executable flags on section .rcd: " + filepath);
    }
    return patched;
}

} // namespace Astral::PEPatcher
