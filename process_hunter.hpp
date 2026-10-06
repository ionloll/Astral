#pragma once

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <string>
#include <vector>
#include <set>
#include <algorithm>
#include <cstring>
#include "config.hpp"
#include "ui.hpp"

#pragma comment(lib, "psapi.lib")

namespace Astral::ProcessHunter {

// Acquires SeDebugPrivilege to permit process termination and cross-process virtual memory queries.
inline bool enable_debug_privilege() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        return false;
    }

    LUID luid = {};
    if (!LookupPrivilegeValueA(nullptr, "SeDebugPrivilege", &luid)) {
        CloseHandle(token);
        return false;
    }

    TOKEN_PRIVILEGES tp = {};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    const bool ok = AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), nullptr, nullptr) &&
                    (GetLastError() == ERROR_SUCCESS);
    CloseHandle(token);
    return ok;
}

// Terminates processes matching target executable image names.
inline int kill_processes_by_name(const std::vector<std::string>& targets) {
    enable_debug_privilege();
    int killed = 0;

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe = {};
    pe.dwSize = sizeof(pe);

    if (Process32FirstW(snap, &pe)) {
        do {
            char name_buf[MAX_PATH] = {};
            WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1, name_buf, sizeof(name_buf), nullptr, nullptr);
            std::string proc_name(name_buf);
            std::string proc_lower = proc_name;
            std::transform(proc_lower.begin(), proc_lower.end(), proc_lower.begin(), ::tolower);

            for (const auto& target : targets) {
                std::string target_lower = target;
                std::transform(target_lower.begin(), target_lower.end(), target_lower.begin(), ::tolower);

                if (proc_lower == target_lower) {
                    HANDLE proc = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                    if (proc) {
                        if (TerminateProcess(proc, 1)) {
                            UI::log_action("Terminated process: " + proc_name + " (PID " + std::to_string(pe.th32ProcessID) + ")");
                            killed++;
                        }
                        CloseHandle(proc);
                    }
                }
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return killed;
}

struct MemoryThreat {
    DWORD pid;
    std::string proc_name;
    std::string reason;
};

// Scans commit memory pages of susceptible host processes for Luckyware loader magic DWORD (0xBA73593C).
inline std::vector<MemoryThreat> scan_shared_memory_signatures() {
    std::vector<MemoryThreat> threats;
    enable_debug_privilege();

    const DWORD sig_val = 0xBA73593C;
    uint8_t sig[4];
    std::memcpy(sig, &sig_val, sizeof(sig));

    static const std::set<std::string> hosts = {
        "dllhost.exe", "svchost.exe", "disksnapshot.exe",
        "fontdrvhost.exe", "icacls.exe", "ktmutil.exe",
        "label.exe", "legacynetuxhost.exe", "licensingdiag.exe"
    };

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return threats;

    PROCESSENTRY32W pe = {};
    pe.dwSize = sizeof(pe);

    if (Process32FirstW(snap, &pe)) {
        do {
            char name_buf[MAX_PATH] = {};
            WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1, name_buf, sizeof(name_buf), nullptr, nullptr);
            std::string name(name_buf);
            std::string lower_name = name;
            std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(), ::tolower);

            if (hosts.count(lower_name)) {
                HANDLE proc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pe.th32ProcessID);
                if (proc) {
                    MEMORY_BASIC_INFORMATION mbi = {};
                    uintptr_t addr = 0;
                    int regions = 0;

                    while (regions < 50) {
                        if (!VirtualQueryEx(proc, reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi))) break;

                        if (mbi.State == MEM_COMMIT && (mbi.Protect & PAGE_READWRITE) && mbi.RegionSize <= 0x100000) {
                            const size_t read_sz = std::min(mbi.RegionSize, static_cast<SIZE_T>(0x10000));
                            std::vector<uint8_t> buf(read_sz);
                            SIZE_T bytes_read = 0;

                            if (ReadProcessMemory(proc, mbi.BaseAddress, buf.data(), read_sz, &bytes_read)) {
                                auto it = std::search(buf.begin(), buf.begin() + bytes_read, sig, sig + 4);
                                if (it != buf.begin() + bytes_read) {
                                    threats.push_back({
                                        pe.th32ProcessID,
                                        name,
                                        "Shared memory signature 0xBA73593C detected (Luckyware loader hook)"
                                    });
                                    break;
                                }
                            }
                            regions++;
                        }
                        addr = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
                        if (addr > 0x7FFFFFFFFFFF) break;
                    }
                    CloseHandle(proc);
                }
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return threats;
}

// Queries known static and parameterized mutex handles instantiated by the malware runtime.
inline std::vector<std::string> scan_mutexes() {
    std::vector<std::string> found;

    static const std::vector<std::pair<std::string, std::string>> static_mutexes = {
        { "Global\\PFLwrx",    "Luckyware payload mutex" },
        { "Global\\PFLwrxMNN", "Luckyware payload secondary mutex" }
    };

    for (const auto& [name, desc] : static_mutexes) {
        HANDLE h = OpenMutexA(SYNCHRONIZE, FALSE, name.c_str());
        if (h) {
            CloseHandle(h);
            found.push_back(name + " (" + desc + ")");
        }
    }

    static const std::vector<std::string> prefixes = { "Global\\PFNMX_", "Global\\PFNX_" };
    static const std::vector<std::string> suffixes = { "test", "1234", "abcd", "ABCD", "0000" };

    for (const auto& p : prefixes) {
        for (const auto& s : suffixes) {
            std::string candidate = p + s;
            HANDLE h = OpenMutexA(SYNCHRONIZE, FALSE, candidate.c_str());
            if (h) {
                CloseHandle(h);
                found.push_back(candidate + " (Luckyware loader mutex)");
            }
        }
    }

    return found;
}

} // namespace Astral::ProcessHunter
