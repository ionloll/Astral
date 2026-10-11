# Astral 🛡️⚡

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20x64-0078D6.svg)](https://microsoft.com)
[![Language](https://img.shields.io/badge/Language-C%2B%2B20-00599C.svg)](https://isocpp.org)
[![Build](https://img.shields.io/badge/Build-MSBuild%20%2F%20Visual%20Studio-5C2D91.svg)](Astral.vcxproj)
[![Author](https://img.shields.io/badge/Author-ion%20(%40ionj)-brightgreen.svg)](https://github.com/ionj)

A high-performance, transparent incident response and forensic toolchain sanitizer written in native modern C++20. Engineered to detect, neutralize, and remediate the **Luckyware (Darkside)** compiler-infector trojan family, persistence vectors, and associated token exfiltration channels.

Maintained and engineered by **ion** ([`@ionj`](https://github.com/ionloll)).

---

## Technical Philosophy: Systems Transparency

Traditional remediation utilities frequently package Python interpreters or run heavily obfuscated scripts that trigger false positives in endpoint detection systems. **Astral** adheres to clear systems programming principles:

1. **Zero External Runtime Dependencies**: Implemented strictly against the Win32 / NT APIs (`Advapi32`, `Psapi`, `Iphlpapi`, `Ws2_32`, `Shell32`). No Python runtimes, no third-party package dependencies, no bundled runtime DLLs.
2. **Transparent Codebase**: Clean, idiomatic C++20 without packing, crypters, or bytecode obfuscation. Auditable by any reverse engineer or static analysis platform.
3. **Surgical Remediation**: In-place PE section de-weaponization (`IMAGE_SCN_MEM_EXECUTE` clearing), tagged and reversible network rules, atomic zero-shredding for transient payloads, and automatic syntax preservation for SDK headers.

---

## Threat Model: Luckyware / Darkside Anatomy

Luckyware is a supply-chain and toolchain infector targeting Windows development environments and community gaming software:

* **SDK Header Poisoning**: Appends obfuscated loaders (`namespace VccLibaries`, `VCCLibraries_wfkuuv...`) into standard Windows SDK headers (primarily `windows.h` and `winnetwk.h`). Any local C++ compilation embeds stage droppers into output binaries.
* **Build System Interception**: Injects rogue `<PreBuildEvent>` tasks into Visual Studio `.vcxproj` definitions and `.suo` streams.
* **PE Section Abuse**: Appends executable stages into non-standard `.rcd` sections or appends nested PE structures (`MZ` signatures).
* **Credential & Session Hijacking**: Places proxy DLLs (`profapi.dll`) into `%LOCALAPPDATA%\Discord\app-*` for search-order execution and injects exfiltration hooks into Electron JavaScript bundles.
* **C2 Channels**: Contacts distributed command-and-control infrastructure (`exo-api.tf`, `devruntime.cy`, `darkside.cy`, etc.) and pushes tokens to disposable Discord webhooks.

---

## Remediation Architecture

| Subsystem | File | Remediation Vector |
| :--- | :--- | :--- |
| **Toolchain Disinfector** | [`sdk_cleaner.hpp`](file:///C:/Users/Administrator/Desktop/Luckyware-Sentinel/sdk_cleaner.hpp) | Audits Windows Kits include trees, cleans rogue namespaces from `windows.h`, and repairs corrupted Microsoft macro epilogues in `winnetwk.h`. |
| **Project Sanitizer** | [`sdk_cleaner.hpp`](file:///C:/Users/Administrator/Desktop/Luckyware-Sentinel/sdk_cleaner.hpp) | Strips malicious `<PreBuildEvent>` nodes from `.vcxproj` files and shreds corrupted `.suo` state files. |
| **PE Section Neutralizer** | [`pe_patcher.hpp`](file:///C:/Users/Administrator/Desktop/Luckyware-Sentinel/pe_patcher.hpp) | Traverses PE section headers, flags rogue `.rcd` sections, and clears `IMAGE_SCN_MEM_EXECUTE` and `IMAGE_SCN_CNT_CODE` in-place. |
| **Network Shield** | [`network_shield.hpp`](file:///C:/Users/Administrator/Desktop/Luckyware-Sentinel/network_shield.hpp) | Applies tagged HOSTS loopback blocks for 40+ C2 domains, registers outbound Windows Firewall drops, and audits active TCP sockets. Reversible in one step. |
| **Process Hunter** | [`process_hunter.hpp`](file:///C:/Users/Administrator/Desktop/Luckyware-Sentinel/process_hunter.hpp) | Elevates to `SeDebugPrivilege`, terminates malware process instances, queries for Luckyware loader memory magic (`0xBA73593C`), and scans active mutex handles. |
| **Credential Guard** | [`persistence_hunter.hpp`](file:///C:/Users/Administrator/Desktop/Luckyware-Sentinel/persistence_hunter.hpp) | Removes Discord search-order proxy DLLs (`profapi.dll`), scrubs injected JavaScript loaders, and audits directories for hardcoded webhook URLs. |
| **Persistence Hunter** | [`persistence_hunter.hpp`](file:///C:/Users/Administrator/Desktop/Luckyware-Sentinel/persistence_hunter.hpp) | Cleans user and machine Run/RunOnce registry entries, startup directories, and chrono-named droppers (`^[A-Za-z]{2,3}\d{10,13}(\.exe)?$`) from temporary roots. |
| **Reporting Subsystem** | [`report_generator.hpp`](file:///C:/Users/Administrator/Desktop/Luckyware-Sentinel/report_generator.hpp) | Exports structured plaintext logs and a dark-mode, responsive HTML security summary with endpoint health metrics. |

---

## Operational Guide

### 1. Interactive Interface
Run `Launch.bat` (or execute `Astral.exe` directly; UAC elevation is requested automatically if non-administrative):
```cmd
Launch.bat
```

### 2. Headless / Command-Line Interface
```cmd
# Full automated remediation (Terminates processes, cleans SDK headers, blocks C2, purges persistence)
Astral.exe --full-clean

# Safe dry-run mode (Audits and reports threats without writing changes)
Astral.exe --full-clean --dry-run

# Targeted directory scan
Astral.exe --scan "C:\Users\Administrator\source\repos"

# Enforce network isolation shield (HOSTS + Firewall)
Astral.exe --block

# Teardown network isolation shield (Removes Astral entries cleanly)
Astral.exe --unblock

# Disinfect Windows SDK headers only
Astral.exe --sdk-clean

# Disinfect Discord installations only
Astral.exe --discord-clean
```

---

## Building from Source

Requires Visual Studio 2022 (v143) or Visual Studio 2026 (v145) with the C++ Desktop workload and Windows SDK:

```cmd
git clone https://github.com/ionloll/Astral.git
cd Astral
msbuild Astral.vcxproj /p:Configuration=Release /p:Platform=x64
```

The output executable is compiled to:
`bin\Release\Astral.exe`

---

## Forensic Reports

Each audit run produces two artifacts in the working directory:
* **`Astral_Report.html`**: Visual dark-mode dashboard detailing security posture score, audited counts, and itemized findings.
* **`Astral_Report.txt`**: Standardized plaintext incident log for ticket attachments and CI runs.

---

## Antivirus False-Positive Transparency

Because Astral acquires `SeDebugPrivilege`, modifies Windows Firewall rules, edits the Windows `HOSTS` file, and parses section characteristics of PE binaries, newly compiled binaries without accumulated cloud reputation may occasionally trigger heuristic alerts on multi-engine scanners.

* Source-to-binary reproducibility is guaranteed by Microsoft-hosted GitHub Actions runners.
* SHA-256 hashes are published on every release tag for verification:
  ```powershell
  Get-FileHash .\Astral.exe -Algorithm SHA256
  ```

---

## License

This project is licensed under the [MIT License](LICENSE).

Developed and maintained by **ion** ([`@ionj`](https://github.com/ionj)).
