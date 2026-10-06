#pragma once

#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <windows.h>
#include "config.hpp"
#include "ui.hpp"

namespace Astral::ReportGenerator {

struct AuditFinding {
    std::string category;
    std::string severity; // "CLEAN", "WARNING", "CRITICAL"
    std::string details;
    std::string action_taken;
};

struct AuditReport {
    std::string scan_time;
    std::string hostname;
    int files_scanned = 0;
    int threats_detected = 0;
    int threats_remediated = 0;
    int health_score = 100;
    std::vector<AuditFinding> findings;
};

inline std::string get_current_time_str() {
    const auto now = std::chrono::system_clock::now();
    const std::time_t tt = std::chrono::system_clock::to_time_t(now);
    std::tm tm_buf = {};
    localtime_s(&tm_buf, &tt);
    char buf[64] = {};
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm_buf);
    return std::string(buf);
}

inline std::string get_computer_name() {
    char buf[MAX_COMPUTERNAME_LENGTH + 1] = {};
    DWORD len = sizeof(buf);
    if (GetComputerNameA(buf, &len)) return std::string(buf);
    return "UNKNOWN-HOST";
}

inline bool export_text_report(const AuditReport& report, const std::string& filename = "Astral_Report.txt") {
    std::ofstream out(filename);
    if (!out.is_open()) return false;

    out << "================================================================================\n";
    out << "                       ASTRAL - INCIDENT AUDIT REPORT                           \n";
    out << "                     Developed by " << Config::AUTHOR << "\n";
    out << "================================================================================\n\n";
    out << "Scan Timestamp  : " << report.scan_time << "\n";
    out << "Host Machine    : " << report.hostname << "\n";
    out << "Files Audited   : " << report.files_scanned << "\n";
    out << "Threats Found   : " << report.threats_detected << "\n";
    out << "Remediated Items: " << report.threats_remediated << "\n";
    out << "Health Score    : " << report.health_score << " / 100\n\n";

    out << "--------------------------------------------------------------------------------\n";
    out << "ITEMIZED AUDIT FINDINGS\n";
    out << "--------------------------------------------------------------------------------\n";

    if (report.findings.empty()) {
        out << "[*] No malicious activity or compiler infections identified. System is clean.\n";
    } else {
        for (const auto& f : report.findings) {
            out << "[" << f.severity << "] " << f.category << "\n";
            out << "  └─ Details: " << f.details << "\n";
            out << "  └─ Action : " << f.action_taken << "\n\n";
        }
    }

    out << "================================================================================\n";
    out << "End of Astral Forensic Audit Report\n";
    out.close();
    return true;
}

inline bool export_html_report(const AuditReport& report, const std::string& filename = "Astral_Report.html") {
    std::ofstream out(filename);
    if (!out.is_open()) return false;

    const std::string score_color = (report.health_score >= 80) ? "#22c55e" : ((report.health_score >= 50) ? "#eab308" : "#ef4444");
    const std::string score_badge = (report.health_score >= 80) ? "SECURE BASELINE" : ((report.health_score >= 50) ? "ATTENTION REQUIRED" : "ACTIVE COMPROMISE DETECTED");

    out << "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n";
    out << "<meta charset=\"UTF-8\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n";
    out << "<title>Astral - Incident Response & Forensic Report</title>\n";
    out << "<style>\n"
        << "  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background: #0b0f19; color: #f1f5f9; margin: 0; padding: 28px; }\n"
        << "  .container { max-width: 980px; margin: 0 auto; }\n"
        << "  .header { display: flex; align-items: center; justify-content: space-between; border-bottom: 1px solid #1e293b; padding-bottom: 24px; }\n"
        << "  .brand { display: flex; align-items: center; gap: 14px; }\n"
        << "  .title { font-size: 28px; font-weight: 800; letter-spacing: -0.02em; color: #38bdf8; }\n"
        << "  .subtitle { color: #94a3b8; font-size: 14px; margin-top: 4px; }\n"
        << "  .card { background: #131b2e; border-radius: 12px; padding: 22px; margin-top: 24px; border: 1px solid #1e293b; box-shadow: 0 4px 20px rgba(0,0,0,0.3); }\n"
        << "  .score-box { text-align: center; padding: 28px; }\n"
        << "  .score-num { font-size: 72px; font-weight: 800; letter-spacing: -0.03em; color: " << score_color << "; }\n"
        << "  .badge { display: inline-block; padding: 5px 14px; border-radius: 9999px; font-size: 12px; font-weight: 700; letter-spacing: 0.05em; text-transform: uppercase; }\n"
        << "  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-top: 20px; }\n"
        << "  .stat { background: #0b0f19; border-radius: 10px; padding: 18px; border: 1px solid #1e293b; text-align: center; }\n"
        << "  .stat-val { font-size: 26px; font-weight: 800; color: #f8fafc; }\n"
        << "  .stat-lbl { font-size: 12px; color: #94a3b8; text-transform: uppercase; font-weight: 600; margin-top: 6px; }\n"
        << "  .table { width: 100%; border-collapse: collapse; margin-top: 18px; }\n"
        << "  .th { text-align: left; padding: 12px; border-bottom: 2px solid #1e293b; color: #94a3b8; font-size: 12px; text-transform: uppercase; }\n"
        << "  .td { padding: 14px 12px; border-bottom: 1px solid #1e293b; font-size: 13px; }\n"
        << "  .badge-CRITICAL { background: #ef4444; color: #ffffff; }\n"
        << "  .badge-WARNING { background: #f59e0b; color: #111827; }\n"
        << "  .badge-CLEAN { background: #10b981; color: #ffffff; }\n"
        << "</style>\n</head>\n<body>\n<div class=\"container\">\n";

    out << "<div class=\"header\">\n"
        << "  <div class=\"brand\">\n"
        << "    <div>\n"
        << "      <div class=\"title\">" << Config::APP_NAME << "</div>\n"
        << "      <div class=\"subtitle\">Automated Incident Response & Toolchain Disinfection &bull; Maintained by " << Config::AUTHOR << "</div>\n"
        << "    </div>\n"
        << "  </div>\n"
        << "  <div class=\"subtitle\">Generated: " << report.scan_time << "</div>\n"
        << "</div>\n";

    out << "<div class=\"card score-box\">\n"
        << "  <div class=\"stat-lbl\">SYSTEM SECURITY HEALTH SCORE</div>\n"
        << "  <div class=\"score-num\">" << report.health_score << "<span style=\"font-size:32px; color:#64748b;\"> / 100</span></div>\n"
        << "  <span class=\"badge\" style=\"background: " << score_color << "; color: #ffffff;\">" << score_badge << "</span>\n"
        << "</div>\n";

    out << "<div class=\"grid\">\n"
        << "  <div class=\"stat\"><div class=\"stat-val\">" << report.files_scanned << "</div><div class=\"stat-lbl\">Files Audited</div></div>\n"
        << "  <div class=\"stat\"><div class=\"stat-val\" style=\"color: " << (report.threats_detected ? "#ef4444" : "#10b981") << "\">" << report.threats_detected << "</div><div class=\"stat-lbl\">Threats Detected</div></div>\n"
        << "  <div class=\"stat\"><div class=\"stat-val\" style=\"color: #38bdf8\">" << report.threats_remediated << "</div><div class=\"stat-lbl\">Remediated Items</div></div>\n"
        << "  <div class=\"stat\"><div class=\"stat-val\">" << report.hostname << "</div><div class=\"stat-lbl\">Host Endpoint</div></div>\n"
        << "</div>\n";

    out << "<div class=\"card\">\n"
        << "  <h3 style=\"margin-top:0; color:#38bdf8; font-size:18px;\">Itemized Forensic Remediation Log</h3>\n"
        << "  <table class=\"table\">\n"
        << "    <tr><th class=\"th\">Severity</th><th class=\"th\">Vector</th><th class=\"th\">Artifact Details</th><th class=\"th\">Action Taken</th></tr>\n";

    if (report.findings.empty()) {
        out << "    <tr><td class=\"td\" colspan=\"4\" style=\"text-align:center; color:#10b981; padding:28px;\">"
            << "✓ System verified clean: No compiler poisoning, persistence items, or exfiltration hooks identified."
            << "</td></tr>\n";
    } else {
        for (const auto& f : report.findings) {
            out << "    <tr>\n"
                << "      <td class=\"td\"><span class=\"badge badge-" << f.severity << "\">" << f.severity << "</span></td>\n"
                << "      <td class=\"td\" style=\"font-weight:600\">" << f.category << "</td>\n"
                << "      <td class=\"td\" style=\"color:#cbd5e1; word-break:break-all;\">" << f.details << "</td>\n"
                << "      <td class=\"td\" style=\"color:#38bdf8; font-weight:500;\">" << f.action_taken << "</td>\n"
                << "    </tr>\n";
        }
    }

    out << "  </table>\n</div>\n";
    out << "<div style=\"text-align:center; margin-top:28px; color:#64748b; font-size:12px;\">\n"
        << "  Astral &bull; Open-Source Systems Defense &bull; Maintained by " << Config::AUTHOR << "\n"
        << "</div>\n</div>\n</body>\n</html>\n";

    out.close();
    return true;
}

} // namespace Astral::ReportGenerator
