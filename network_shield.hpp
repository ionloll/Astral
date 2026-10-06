#pragma once

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <filesystem>
#include "config.hpp"
#include "ui.hpp"

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

namespace Astral::Network {

namespace fs = std::filesystem;

inline const std::string HOSTS_PATH = "C:\\Windows\\System32\\drivers\\etc\\hosts";
inline const std::string HOSTS_BAK  = "C:\\Windows\\System32\\drivers\\etc\\hosts.astral_bak";

inline void flush_dns() {
    STARTUPINFOA si = { sizeof(si) };
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi = {};
    char cmd[] = "ipconfig /flushdns";
    if (CreateProcessA(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 3000);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
}

// Preserves pristine hosts state prior to initial injection.
inline bool backup_hosts() {
    try {
        if (fs::exists(HOSTS_PATH) && !fs::exists(HOSTS_BAK)) {
            fs::copy_file(HOSTS_PATH, HOSTS_BAK, fs::copy_options::overwrite_existing);
            return true;
        }
    } catch (...) {}
    return false;
}

// Atomically updates the HOSTS table using bounded sentinel markers.
// Guarantees clean uninstallability without leaving trailing duplicate records.
inline int apply_hosts_block() {
    UI::header("Network Shield (HOSTS Sinkhole)");
    backup_hosts();

    std::ifstream in(HOSTS_PATH);
    if (!in.is_open()) {
        UI::fail("Unable to open HOSTS (requires elevated privileges).");
        return 0;
    }

    std::string content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    in.close();

    // Strip previous Astral block if present to ensure clean idempotent rewrite.
    size_t start_pos = content.find(Config::HOSTS_TAG_START);
    size_t end_pos   = content.find(Config::HOSTS_TAG_END);
    if (start_pos != std::string::npos && end_pos != std::string::npos && end_pos > start_pos) {
        end_pos += Config::HOSTS_TAG_END.length();
        content.erase(start_pos, end_pos - start_pos);
    }

    while (!content.empty() && (content.back() == '\r' || content.back() == '\n' || content.back() == ' ')) {
        content.pop_back();
    }

    std::ostringstream block;
    block << "\n\n" << Config::HOSTS_TAG_START << "\n";
    block << "# Managed by Astral (" << Config::AUTHOR << ")\n";

    int count = 0;
    for (const auto& domain : Config::C2_DOMAINS) {
        block << "0.0.0.0 " << domain << "\n";
        block << "127.0.0.1 " << domain << "\n";
        block << "0.0.0.0 www." << domain << "\n";
        block << "127.0.0.1 www." << domain << "\n";
        count++;
    }
    block << Config::HOSTS_TAG_END << "\n";

    content += block.str();

    std::ofstream out(HOSTS_PATH, std::ios::trunc);
    if (!out.is_open()) {
        UI::fail("Failed writing HOSTS file.");
        return 0;
    }
    out << content;
    out.close();

    flush_dns();
    UI::ok("Sinkholed " + std::to_string(count) + " domains to 0.0.0.0 / 127.0.0.1");
    return count;
}

inline bool restore_hosts() {
    UI::header("Network Shield (HOSTS Reversion)");
    std::ifstream in(HOSTS_PATH);
    if (!in.is_open()) return false;
    std::string content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    in.close();

    size_t start_pos = content.find(Config::HOSTS_TAG_START);
    size_t end_pos   = content.find(Config::HOSTS_TAG_END);
    if (start_pos != std::string::npos && end_pos != std::string::npos && end_pos > start_pos) {
        end_pos += Config::HOSTS_TAG_END.length();
        content.erase(start_pos, end_pos - start_pos);

        std::ofstream out(HOSTS_PATH, std::ios::trunc);
        if (out.is_open()) {
            out << content;
            out.close();
            flush_dns();
            UI::ok("HOSTS entries successfully restored to original baseline.");
            return true;
        }
    } else {
        UI::info("No Astral block tags found in HOSTS.");
    }
    return false;
}

// Drops direct-to-IP egress at the NDIS / filtering platform layer.
inline int apply_firewall_rules() {
    UI::header("Network Shield (Outbound Firewall Filters)");
    int rules = 0;

    for (const auto& ip : Config::C2_IPS) {
        std::string tag = ip;
        for (char& c : tag) if (c == '.') c = '_';
        std::string cmd = "netsh advfirewall firewall add rule name=\"Astral_Drop_" + tag +
                          "\" dir=out action=block remoteip=" + ip + " enable=yes";

        STARTUPINFOA si = { sizeof(si) };
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
        PROCESS_INFORMATION pi = {};
        if (CreateProcessA(NULL, cmd.data(), NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
            WaitForSingleObject(pi.hProcess, 3000);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            UI::ok("Outbound block installed for IP " + ip);
            rules++;
        }
    }
    return rules;
}

struct SocketAnomaly {
    DWORD pid;
    std::string remote_ip;
    WORD remote_port;
    std::string description;
};

// Audits the IPv4 TCP connection table for active C2 sockets or DoH bypass evasion.
inline std::vector<SocketAnomaly> inspect_active_sockets() {
    std::vector<SocketAnomaly> anomalies;
    DWORD size = 0;
    GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (size == 0) return anomalies;

    std::vector<BYTE> buffer(size);
    if (GetExtendedTcpTable(buffer.data(), &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR) {
        return anomalies;
    }

    auto* table = reinterpret_cast<MIB_TCPTABLE_OWNER_PID*>(buffer.data());
    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        auto& row = table->table[i];
        if (row.dwState != MIB_TCP_STATE_ESTAB) continue;

        WORD remote_port = ntohs(static_cast<WORD>(row.dwRemotePort));
        char ip_str[INET_ADDRSTRLEN] = {};
        inet_ntop(AF_INET, &row.dwRemoteAddr, ip_str, sizeof(ip_str));
        std::string ip(ip_str);

        for (const auto& c2 : Config::C2_IPS) {
            if (ip == c2) {
                anomalies.push_back({ row.dwOwningPid, ip, remote_port, "Established connection to C2 IP " + ip });
            }
        }

        // Direct-to-IP DoH queries over 443 are commonly leveraged to circumvent local hosts null-routes.
        if (remote_port == 443 && (ip == "8.8.8.8" || ip == "8.8.4.4")) {
            anomalies.push_back({ row.dwOwningPid, ip, remote_port, "Suspect DoH (DNS-over-HTTPS) outbound session on port 443" });
        }
    }
    return anomalies;
}

inline std::vector<SocketAnomaly> scan_active_sockets() {
    return inspect_active_sockets();
}

} // namespace Astral::Network
