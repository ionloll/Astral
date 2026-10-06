#pragma once

#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <atomic>
#include <filesystem>
#include <set>
#include <algorithm>
#include "config.hpp"
#include "ui.hpp"
#include "pe_patcher.hpp"
#include "sdk_cleaner.hpp"
#include "report_generator.hpp"

namespace Astral::Engine {

namespace fs = std::filesystem;

struct ScanConfig {
    std::vector<std::string> scan_paths;
    bool auto_remediate = true;
    bool dry_run = false;
    int num_threads = 8;
};

// Multithreaded file discovery and parallel heuristic scanning engine.
inline ReportGenerator::AuditReport run_engine_scan(const ScanConfig& cfg) {
    ReportGenerator::AuditReport report;
    report.scan_time = ReportGenerator::get_current_time_str();
    report.hostname  = ReportGenerator::get_computer_name();

    std::vector<std::string> file_queue;
    static const std::set<std::string> skip_dirs = {
        "$recycle.bin", "system volume information", "windows\\winsxs",
        ".git", "node_modules", ".vs", "quarantine", "luckyware-sentinel", "astral"
    };

    UI::section_header("Scanner - File Discovery & Target Staging");
    UI::log_info("Traversing file trees for target file extensions...");

    for (const auto& root_str : cfg.scan_paths) {
        if (!fs::exists(root_str)) continue;
        try {
            for (const auto& entry : fs::recursive_directory_iterator(root_str, fs::directory_options::skip_permission_denied)) {
                if (!entry.is_regular_file()) continue;

                std::string path_lower = entry.path().string();
                std::transform(path_lower.begin(), path_lower.end(), path_lower.begin(), ::tolower);

                bool skip = false;
                for (const auto& s : skip_dirs) {
                    if (path_lower.find(s) != std::string::npos) {
                        skip = true;
                        break;
                    }
                }
                if (skip) continue;

                std::string ext = entry.path().extension().string();
                std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);

                if (Config::SCAN_EXTENSIONS.count(ext) || entry.path().filename() == ".suo") {
                    file_queue.push_back(entry.path().string());
                }
            }
        } catch (...) {}
    }

    const int total_files = static_cast<int>(file_queue.size());
    report.files_scanned = total_files;
    UI::log_success("Collected " + std::to_string(total_files) + " candidates for inspection.");

    if (total_files == 0) return report;

    UI::section_header("Multithreaded Inspection Pipeline");
    UI::ProgressBar progress(total_files);

    std::atomic<int> file_index{0};
    std::mutex report_mutex;
    std::vector<std::thread> workers;

    auto worker_task = [&]() {
        while (true) {
            const int idx = file_index.fetch_add(1, std::memory_order_relaxed);
            if (idx >= total_files) break;

            const std::string& fpath = file_queue[idx];
            std::string ext = fs::path(fpath).extension().string();
            std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
            std::string fname = fs::path(fpath).filename().string();
            std::transform(fname.begin(), fname.end(), fname.begin(), ::tolower);

            // 1. Portable Executable Inspection (.exe, .dll)
            if (ext == ".exe" || ext == ".dll") {
                const auto pe_res = PEPatcher::analyze_pe(fpath);
                if (pe_res.is_infected) {
                    progress.add_threat();
                    std::string action = "Flagged (Dry-Run)";
                    if (cfg.auto_remediate && !cfg.dry_run) {
                        if (pe_res.has_rcd_executable) {
                            PEPatcher::neutralize_pe_section(fpath);
                            action = "Neutralized executable flag on .rcd section";
                        } else {
                            PEPatcher::shred_file(fpath);
                            action = "Securely shredded and deleted";
                        }
                    }
                    {
                        std::lock_guard<std::mutex> lk(report_mutex);
                        report.threats_detected++;
                        if (cfg.auto_remediate && !cfg.dry_run) report.threats_remediated++;
                        report.findings.push_back({
                            "Executable Payload",
                            "CRITICAL",
                            fpath + " (" + pe_res.detection_reason + ")",
                            action
                        });
                    }
                }
            }
            // 2. Visual Studio C++ Project Files (.vcxproj)
            else if (ext == ".vcxproj") {
                const bool cleaned = SDKCleaner::clean_vcxproj(fpath, cfg.dry_run);
                if (cleaned) {
                    progress.add_threat();
                    {
                        std::lock_guard<std::mutex> lk(report_mutex);
                        report.threats_detected++;
                        if (!cfg.dry_run) report.threats_remediated++;
                        report.findings.push_back({
                            "MSBuild Project",
                            "CRITICAL",
                            fpath + " (Malicious PreBuildEvent dropper)",
                            cfg.dry_run ? "Flagged (Dry-Run)" : "Removed PreBuildEvent injection"
                        });
                    }
                }
            }
            // 3. Visual Studio Solution Options (.suo)
            else if (ext == ".suo" || fname == ".suo") {
                const bool cleaned = SDKCleaner::clean_suo(fpath, cfg.dry_run);
                if (cleaned) {
                    progress.add_threat();
                    {
                        std::lock_guard<std::mutex> lk(report_mutex);
                        report.threats_detected++;
                        if (!cfg.dry_run) report.threats_remediated++;
                        report.findings.push_back({
                            "Solution Options",
                            "WARNING",
                            fpath + " (Infected SUO user options stream)",
                            cfg.dry_run ? "Flagged (Dry-Run)" : "Purged and deleted"
                        });
                    }
                }
            }
            // 4. Source Files (ImGui & C++ modules)
            else if (ext == ".cpp" || ext == ".h" || ext == ".hpp") {
                const bool cleaned = SDKCleaner::clean_imgui_file(fpath, cfg.dry_run);
                if (cleaned) {
                    progress.add_threat();
                    {
                        std::lock_guard<std::mutex> lk(report_mutex);
                        report.threats_detected++;
                        if (!cfg.dry_run) report.threats_remediated++;
                        report.findings.push_back({
                            "Source Code Injection",
                            "CRITICAL",
                            fpath + " (Embedded hex payload & system invocations)",
                            cfg.dry_run ? "Flagged (Dry-Run)" : "Disinfected source file"
                        });
                    }
                }
            }

            progress.update(1);
        }
    };

    const int thread_count = std::max<int>(1, cfg.num_threads);
    for (int i = 0; i < thread_count; ++i) {
        workers.emplace_back(worker_task);
    }
    for (auto& w : workers) {
        if (w.joinable()) w.join();
    }

    progress.finish();

    const int deductions = report.threats_detected * 15;
    report.health_score = std::max<int>(0, 100 - deductions);

    return report;
}

} // namespace Astral::Engine
