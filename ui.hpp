#pragma once

#include <iostream>
#include <string>
#include <string_view>
#include <chrono>
#include <atomic>
#include <mutex>
#include <iomanip>
#include <windows.h>

namespace Astral::UI {

inline std::mutex g_io_mutex;

namespace Color {
    inline constexpr std::string_view Reset   = "\033[0m";
    inline constexpr std::string_view Bold    = "\033[1m";
    inline constexpr std::string_view Dim     = "\033[2m";
    inline constexpr std::string_view Red     = "\033[91m";
    inline constexpr std::string_view Green   = "\033[92m";
    inline constexpr std::string_view Yellow  = "\033[93m";
    inline constexpr std::string_view Cyan    = "\033[96m";
    inline constexpr std::string_view White   = "\033[97m";
    inline constexpr std::string_view Gray    = "\033[90m";

    inline constexpr std::string_view RESET   = Reset;
    inline constexpr std::string_view BOLD    = Bold;
    inline constexpr std::string_view RED     = Red;
    inline constexpr std::string_view GREEN   = Green;
    inline constexpr std::string_view YELLOW  = Yellow;
    inline constexpr std::string_view CYAN    = Cyan;
    inline constexpr std::string_view WHITE   = White;
    inline constexpr std::string_view BWHITE  = "\033[1;97m";
    inline constexpr std::string_view BGREEN  = "\033[1;92m";
    inline constexpr std::string_view BCYAN   = "\033[1;96m";
    inline constexpr std::string_view BYELLOW = "\033[1;93m";
}

namespace Colors = Color;

inline void init_console() {
    HANDLE handle = GetStdHandle(STD_OUTPUT_HANDLE);
    if (handle != INVALID_HANDLE_VALUE) {
        DWORD mode = 0;
        GetConsoleMode(handle, &mode);
        SetConsoleMode(handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    }
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
}

inline void init_terminal() {
    init_console();
}

inline void set_title(std::string_view title) {
    SetConsoleTitleA(std::string(title).c_str());
}

inline void info(std::string_view msg) {
    std::lock_guard<std::mutex> lock(g_io_mutex);
    std::cout << "  " << Color::Cyan << "::" << Color::Reset << " " << msg << "\n";
}

inline void ok(std::string_view msg) {
    std::lock_guard<std::mutex> lock(g_io_mutex);
    std::cout << "  " << Color::Green << "✓" << Color::Reset << " " << msg << "\n";
}

inline void warn(std::string_view msg) {
    std::lock_guard<std::mutex> lock(g_io_mutex);
    std::cout << "  " << Color::Yellow << "!" << Color::Reset << " " << msg << "\n";
}

inline void fail(std::string_view msg) {
    std::lock_guard<std::mutex> lock(g_io_mutex);
    std::cout << "  " << Color::Red << "✗" << Color::Reset << " " << msg << "\n";
}

inline void act(std::string_view action, std::string_view target) {
    std::lock_guard<std::mutex> lock(g_io_mutex);
    std::cout << "  " << Color::Yellow << "→ " << Color::Reset << action << ": "
              << Color::Dim << target << Color::Reset << "\n";
}

inline void header(std::string_view title) {
    std::lock_guard<std::mutex> lock(g_io_mutex);
    std::cout << "\n  " << Color::Bold << Color::White << title << Color::Reset << "\n"
              << "  " << Color::Gray << std::string(title.length(), '-') << Color::Reset << "\n";
}

inline void banner() {
    using namespace Color;
    std::cout << "\n"
              << "  " << Cyan << Bold << "✦ ASTRAL ✦" << Reset << " " 
              << Gray << "v3.2.0" << Reset << "\n"
              << "  " << Dim  << "Incident Response & Toolchain Sanitizer" << Reset << "\n"
              << "  " << Gray << "Maintained by ion (@ionj)" << Reset << "\n\n";
}

inline void log_info(std::string_view msg) { info(msg); }
inline void log_success(std::string_view msg) { ok(msg); }
inline void log_warning(std::string_view msg) { warn(msg); }
inline void log_threat(std::string_view msg) { fail(msg); }
inline void log_action(std::string_view msg) { act("Remediate", msg); }
inline void section_header(std::string_view title) { header(title); }
inline void print_banner() { banner(); }

inline void notify(std::string_view title, std::string_view msg) {
    std::string cmd = "powershell -NoP -NonI -W Hidden -Command \""
        "[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null; "
        "$xml = [Windows.Data.Xml.Dom.XmlDocument]::new(); "
        "$xml.LoadXml('<toast><visual><binding template=\\\"ToastText02\\\"><text id=\\\"1\\\">" + std::string(title) +
        "</text><text id=\\\"2\\\">" + std::string(msg) + "</text></binding></visual></toast>'); "
        "[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('Astral').Show([Windows.UI.Notifications.ToastNotification]::new($xml))\"";

    STARTUPINFOA si = { sizeof(si) };
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi = {};
    if (CreateProcessA(NULL, cmd.data(), NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
}

inline void toast_notification(std::string_view title, std::string_view msg) {
    notify(title, msg);
}

class Progress {
private:
    int m_total;
    std::atomic<int> m_done{0};
    std::atomic<int> m_threats{0};
    std::chrono::steady_clock::time_point m_start{std::chrono::steady_clock::now()};
    static constexpr int BAR_WIDTH = 32;

public:
    explicit Progress(int total) : m_total(total) {}

    void hit() { m_threats.fetch_add(1, std::memory_order_relaxed); }
    void add_threat() { hit(); }

    void step(int n = 1) {
        m_done.fetch_add(n, std::memory_order_relaxed);
        render();
    }
    void update(int n = 1) { step(n); }

    void render() {
        std::lock_guard<std::mutex> lock(g_io_mutex);
        int done = m_done.load();
        if (m_total <= 0) return;

        double pct = static_cast<double>(done) / m_total;
        int filled = static_cast<int>(BAR_WIDTH * pct);

        auto now = std::chrono::steady_clock::now();
        double elapsed = std::chrono::duration<double>(now - m_start).count();
        double rate = elapsed > 0.05 ? done / elapsed : 0.0;
        double rem = rate > 0.0 ? (m_total - done) / rate : 0.0;

        std::string bar;
        bar.reserve(BAR_WIDTH);
        for (int i = 0; i < filled; ++i) bar += "#";
        for (int i = filled; i < BAR_WIDTH; ++i) bar += "-";

        std::cout << "\033[2K\r  "
                  << Color::Cyan << "[" << bar << "] " << Color::Reset
                  << std::setw(3) << static_cast<int>(pct * 100) << "% "
                  << Color::Gray << done << "/" << m_total << Color::Reset
                  << "  " << Color::Dim << static_cast<int>(rate) << " f/s"
                  << "  eta " << static_cast<int>(rem) << "s" << Color::Reset
                  << (m_threats.load() > 0 ? (std::string("  ") + std::string(Color::Red) + "threats: " + std::to_string(m_threats.load()) + std::string(Color::Reset)) : "")
                  << std::flush;
    }

    void done() {
        std::lock_guard<std::mutex> lock(g_io_mutex);
        std::cout << "\033[2K\r  " << Color::Green << "✓" << Color::Reset << " Scanned "
                  << m_done.load() << " files (" << m_threats.load() << " threats found)\n";
    }
    void finish() { done(); }
};

using ProgressBar = Progress;

} // namespace Astral::UI
