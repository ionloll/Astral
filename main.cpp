#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <shellapi.h>
#include <iostream>
#include <string>
#include <vector>
#include <filesystem>
#include "config.hpp"
#include "ui.hpp"
#include "network_shield.hpp"
#include "sdk_cleaner.hpp"
#include "pe_patcher.hpp"
#include "process_hunter.hpp"
#include "persistence_hunter.hpp"
#include "report_generator.hpp"
#include "engine.hpp"

#pragma comment(lib, "shell32.lib")

namespace fs = std::filesystem;
using namespace Astral;

// Verifies caller process token membership in local Administrators group (RID 544).
inline bool is_running_as_admin() {
    BOOL is_admin = FALSE;
    SID_IDENTIFIER_AUTHORITY nt_auth = SECURITY_NT_AUTHORITY;
    PSID admin_group = nullptr;
    if (AllocateAndInitializeSid(&nt_auth, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &admin_group)) {
        CheckTokenMembership(nullptr, admin_group, &is_admin);
        FreeSid(admin_group);
    }
    return is_admin == TRUE;
}

// Spawns elevated instance with 'runas' verb to handle privileged operations.
inline void relaunch_as_admin(int argc, char* argv[]) {
    char exe_path[MAX_PATH] = {};
    GetModuleFileNameA(NULL, exe_path, MAX_PATH);

    std::string args_str = "";
    for (int i = 1; i < argc; ++i) {
        args_str += "\"" + std::string(argv[i]) + "\" ";
    }

    SHELLEXECUTEINFOA sei = { sizeof(sei) };
    sei.lpVerb = "runas";
    sei.lpFile = exe_path;
    sei.lpParameters = args_str.c_str();
    sei.nShow = SW_NORMAL;

    if (ShellExecuteExA(&sei)) {
        exit(0);
    }
}

// Executes end-to-end incident response sequence across all attack vectors.
inline ReportGenerator::AuditReport execute_full_remediation(bool dry_run = false) {
    UI::section_header("Executing Incident Remediation Pipeline");

    ReportGenerator::AuditReport report;
    report.scan_time = ReportGenerator::get_current_time_str();
    report.hostname  = ReportGenerator::get_computer_name();

    // Stage 1: Active Process & Memory Inspection
    UI::log_info("Stage 1/7: Terminating active malware processes & inspecting memory...");
    const int killed = ProcessHunter::kill_processes_by_name(Config::MALWARE_BINARIES);
    if (killed > 0) {
        report.threats_detected += killed;
        report.threats_remediated += killed;
        report.findings.push_back({
            "Active Process",
            "CRITICAL",
            "Terminated " + std::to_string(killed) + " malware processes",
            "Process Terminated"
        });
    }

    const auto mem_threats = ProcessHunter::scan_shared_memory_signatures();
    for (const auto& mt : mem_threats) {
        report.threats_detected++;
        report.findings.push_back({
            "Memory Injection",
            "CRITICAL",
            "PID " + std::to_string(mt.pid) + " (" + mt.proc_name + "): " + mt.reason,
            "Flagged"
        });
    }

    // Stage 2: Network Perimeter Containment
    UI::log_info("Stage 2/7: Isolating C2 network channels (HOSTS loopback & firewall drops)...");
    if (!dry_run) {
        Network::apply_hosts_block();
        Network::apply_firewall_rules();
    }
    const auto sock_threats = Network::scan_active_sockets();
    for (const auto& st : sock_threats) {
        report.threats_detected++;
        report.findings.push_back({
            "Network Socket",
            "WARNING",
            "PID " + std::to_string(st.pid) + " active connection to " + st.remote_ip + ":" + std::to_string(st.remote_port),
            "Flagged"
        });
    }

    // Stage 3: Compiler Toolchain & SDK Disinfection
    UI::log_info("Stage 3/7: Auditing Windows SDK include headers & MSBuild projects...");
    const auto disinfected_headers = SDKCleaner::clean_windows_sdk(dry_run);
    for (const auto& h : disinfected_headers) {
        report.threats_detected++;
        report.threats_remediated++;
        report.findings.push_back({
            "Windows SDK Header",
            "CRITICAL",
            h + " (Injected payload vector)",
            "Disinfected & Epilogue Restored"
        });
    }

    // Stage 4: Credential & Messaging Client Remediation
    UI::log_info("Stage 4/7: Neutralizing Discord DLL proxies & injected script hooks...");
    ProcessHunter::kill_processes_by_name({ "Discord.exe", "DiscordCanary.exe", "DiscordPTB.exe" });
    const int discord_cleaned = PersistenceHunter::disinfect_discord(dry_run);
    if (discord_cleaned > 0) {
        report.threats_detected += discord_cleaned;
        report.threats_remediated += discord_cleaned;
        report.findings.push_back({
            "Discord Client",
            "CRITICAL",
            "Removed " + std::to_string(discord_cleaned) + " rogue DLL proxies/JS hooks",
            "Purged & Cleaned"
        });
    }

    // Stage 5: Persistence Mechanisms & Staging Trees
    UI::log_info("Stage 5/7: Scanning registry Run keys and temporary staging roots...");
    const int reg_cleaned = PersistenceHunter::clean_registry_persistence(dry_run);
    if (reg_cleaned > 0) {
        report.threats_detected += reg_cleaned;
        report.threats_remediated += reg_cleaned;
        report.findings.push_back({
            "Registry Persistence",
            "CRITICAL",
            "Removed " + std::to_string(reg_cleaned) + " Run/RunOnce persistence entries",
            "Deleted"
        });
    }

    const int startup_cleaned = PersistenceHunter::scan_startup_folders(dry_run);
    if (startup_cleaned > 0) {
        report.threats_detected += startup_cleaned;
        report.threats_remediated += startup_cleaned;
        report.findings.push_back({
            "Startup Folder",
            "CRITICAL",
            "Removed " + std::to_string(startup_cleaned) + " startup payload items",
            "Deleted"
        });
    }

    const int dropped_purged = PersistenceHunter::purge_staged_payloads(dry_run);
    if (dropped_purged > 0) {
        report.threats_detected += dropped_purged;
        report.threats_remediated += dropped_purged;
        report.findings.push_back({
            "Staged Dropper",
            "CRITICAL",
            "Purged " + std::to_string(dropped_purged) + " staged binaries",
            "Shredded"
        });
    }

    PersistenceHunter::clean_edge_policy_hijacks(dry_run);

    // Stage 6: Parallel File Traversal & PE Section Heuristics
    UI::log_info("Stage 6/7: Executing parallel heuristic inspection across user profile...");
    Engine::ScanConfig scfg;
    scfg.auto_remediate = !dry_run;
    scfg.dry_run = dry_run;

    const std::string user_prof = PersistenceHunter::get_env_var("USERPROFILE");
    if (!user_prof.empty()) scfg.scan_paths.push_back(user_prof);
    const std::string temp_p = PersistenceHunter::get_env_var("TEMP");
    if (!temp_p.empty()) scfg.scan_paths.push_back(temp_p);

    const auto engine_rep = Engine::run_engine_scan(scfg);
    report.files_scanned += engine_rep.files_scanned;
    report.threats_detected += engine_rep.threats_detected;
    report.threats_remediated += engine_rep.threats_remediated;
    for (const auto& f : engine_rep.findings) {
        report.findings.push_back(f);
    }

    // Stage 7: Report Generation & Security Posture Synthesis
    UI::log_info("Stage 7/7: Compiling final security audit reports...");
    const int deductions = report.threats_detected * 10;
    report.health_score = std::max<int>(0, 100 - deductions);

    ReportGenerator::export_text_report(report, "Astral_Report.txt");
    ReportGenerator::export_html_report(report, "Astral_Report.html");

    UI::section_header("Disinfection Summary");
    UI::log_success("Incident remediation sequence complete.");
    UI::log_info("Threats Detected: " + std::to_string(report.threats_detected) +
                 " | Neutralized: " + std::to_string(report.threats_remediated));
    UI::log_info("System Security Score: " + std::to_string(report.health_score) + " / 100");
    UI::log_success("Reports generated: Astral_Report.html & Astral_Report.txt");

    if (report.threats_detected > 0) {
        UI::toast_notification("Astral Security", "Remediation complete: " + std::to_string(report.threats_remediated) + " threats neutralized.");
    } else {
        UI::toast_notification("Astral Security", "Audit complete. No active malware vectors detected.");
    }

    return report;
}

inline void show_menu() {
    while (true) {
        UI::print_banner();
        std::cout << "  " << UI::Colors::BWHITE << "Select an action:\n" << UI::Colors::RESET;
        std::cout << "  " << UI::Colors::BGREEN  << "[1]" << UI::Colors::RESET << " Full Disinfection & Remediation (Recommended)\n";
        std::cout << "  " << UI::Colors::BCYAN   << "[2]" << UI::Colors::RESET << " Threat Audit (Scan Only - Safe Dry-Run)\n";
        std::cout << "  " << UI::Colors::BYELLOW << "[3]" << UI::Colors::RESET << " Network Shield (Enforce HOSTS & Firewall Null-Route)\n";
        std::cout << "  " << UI::Colors::WHITE   << "[4]" << UI::Colors::RESET << " Network Shield Teardown (Remove Astral Host Entries)\n";
        std::cout << "  " << UI::Colors::WHITE   << "[5]" << UI::Colors::RESET << " Toolchain Disinfection (Windows SDK Headers & .vcxproj Projects)\n";
        std::cout << "  " << UI::Colors::WHITE   << "[6]" << UI::Colors::RESET << " Credential & Discord Guard (Purge profapi.dll & Rogue Hooks)\n";
        std::cout << "  " << UI::Colors::WHITE   << "[7]" << UI::Colors::RESET << " Custom Directory Audit\n";
        std::cout << "  " << UI::Colors::WHITE   << "[8]" << UI::Colors::RESET << " Open Latest HTML Incident Report\n";
        std::cout << "  " << UI::Colors::RED     << "[9]" << UI::Colors::RESET << " Exit\n";
        std::cout << "\n  " << UI::Colors::BYELLOW << "Choice [1-9]: " << UI::Colors::RESET;

        std::string choice;
        std::getline(std::cin, choice);

        if (choice == "1") {
            execute_full_remediation(false);
            std::cout << "\n  Press Enter to return to menu...";
            std::cin.get();
        } else if (choice == "2") {
            execute_full_remediation(true);
            std::cout << "\n  Press Enter to return to menu...";
            std::cin.get();
        } else if (choice == "3") {
            Network::apply_hosts_block();
            Network::apply_firewall_rules();
            std::cout << "\n  Press Enter to return to menu...";
            std::cin.get();
        } else if (choice == "4") {
            Network::restore_hosts();
            std::cout << "\n  Press Enter to return to menu...";
            std::cin.get();
        } else if (choice == "5") {
            SDKCleaner::clean_windows_sdk(false);
            std::cout << "\n  Press Enter to return to menu...";
            std::cin.get();
        } else if (choice == "6") {
            PersistenceHunter::disinfect_discord(false);
            std::cout << "\n  Press Enter to return to menu...";
            std::cin.get();
        } else if (choice == "7") {
            std::cout << "  Enter folder path to audit: ";
            std::string path;
            std::getline(std::cin, path);
            if (!path.empty() && fs::exists(path)) {
                Engine::ScanConfig scfg;
                scfg.scan_paths.push_back(path);
                scfg.auto_remediate = true;
                auto rep = Engine::run_engine_scan(scfg);
                ReportGenerator::export_html_report(rep, "Astral_Report.html");
                ReportGenerator::export_text_report(rep, "Astral_Report.txt");
            } else {
                UI::log_warning("Invalid or non-existent path.");
            }
            std::cout << "\n  Press Enter to return to menu...";
            std::cin.get();
        } else if (choice == "8") {
            if (fs::exists("Astral_Report.html")) {
                ShellExecuteA(NULL, "open", "Astral_Report.html", NULL, NULL, SW_SHOWNORMAL);
            } else {
                UI::log_warning("No report generated yet. Run an audit first.");
            }
            std::cout << "\n  Press Enter to return to menu...";
            std::cin.get();
        } else if (choice == "9") {
            break;
        }
    }
}

int main(int argc, char* argv[]) {
    UI::init_terminal();

    if (!is_running_as_admin()) {
        UI::print_banner();
        UI::log_warning("Administrator privileges required for incident remediation.");
        UI::log_info("Requesting elevation via UAC...");
        relaunch_as_admin(argc, argv);
        return 0;
    }

    if (argc > 1) {
        bool dry_run = false;
        bool full_clean = false;
        std::string scan_path = "";

        for (int i = 1; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "--dry-run") dry_run = true;
            else if (arg == "--full-clean") full_clean = true;
            else if (arg == "--block") {
                Network::apply_hosts_block();
                Network::apply_firewall_rules();
                return 0;
            } else if (arg == "--unblock") {
                Network::restore_hosts();
                return 0;
            } else if (arg == "--sdk-clean") {
                SDKCleaner::clean_windows_sdk(false);
                return 0;
            } else if (arg == "--discord-clean") {
                PersistenceHunter::disinfect_discord(false);
                return 0;
            } else if (arg == "--scan" && i + 1 < argc) {
                scan_path = argv[++i];
            }
        }

        if (full_clean) {
            execute_full_remediation(dry_run);
            return 0;
        }

        if (!scan_path.empty()) {
            Engine::ScanConfig scfg;
            scfg.scan_paths.push_back(scan_path);
            scfg.dry_run = dry_run;
            scfg.auto_remediate = !dry_run;
            const auto rep = Engine::run_engine_scan(scfg);
            ReportGenerator::export_html_report(rep, "Astral_Report.html");
            ReportGenerator::export_text_report(rep, "Astral_Report.txt");
            return 0;
        }
    }

    show_menu();
    return 0;
}
