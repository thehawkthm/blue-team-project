# Project 1: Anomalous Windows Command Shell Execution (MITRE ATT&CK T1059.003)

## 📌 Executive Summary
This project demonstrates a Purple Team simulation focused on **Execution Tactic via Windows Command Shell (MITRE T1059.003)**. The goal is to simulate an adversary attempting to execute commands using an obfuscated, backgrounded `cmd.exe` process, detect the telemetry utilizing advanced host forensics tools, and perform incident mitigation (response).

---

## 🛑 Phase 1: The Attack (Red Team Simulation)
Adversaries frequently leverage native binaries (*LOLBINs*) like `cmd.exe` to blend in with legitimate system activities. In this scenario, the adversary injects an argument list and enforces an invisible window style to bypass visual detection by the end-user.

### Command Executed (PowerShell Elevated):
```powershell
Start-Process cmd.exe -WindowStyle Hidden -ArgumentList "/c timeout /t 300"
```

### Syntax Breakdown:
*   `Start-Process cmd.exe`: Launches the native Windows Command Prompt binary.
*   `-WindowStyle Hidden`: Suppresses the graphical user interface (GUI) window, forcing the process to execute strictly in the background.
*   `-ArgumentList`: Passes arguments directly into the newly spawned process.
*   `"/c timeout /t 300"`: Instructs `cmd.exe` to execute a 5-minute countdown (`timeout`) and self-terminate (`/c`) immediately afterward to evade persistent memory footprint analysis.

---

## 🔍 Phase 2: Telemetry & Detection (Blue Team Analysis)

### 1. Process Tree Analysis (Process Explorer)
When analyzing the volatile memory using **Process Explorer** (executed with Administrative privileges), the backgrounded anomaly becomes visible within the process tree hierarchy:
*   **Parent Process:** `powershell.exe`
*   **Child Process:** `cmd.exe`
*   **Grandchild Process:** `timeout.exe`

*Note: Even though `-WindowStyle Hidden` was supplied, Windows maps an invisible `conhost.exe` (Console Window Host) instance underneath `cmd.exe` to handle internal I/O operations.*

### 2. Volatile Memory & CLI Inspection
Inspecting the process properties under the **Image** tab reveals the truncated arguments received by the child process under the `Command Line` metadata field:
`"C:\Windows\system32\cmd.exe" /c timeout /t 300`

### 3. Forensic Log Recovery (PSReadLine History)
To uncover the full context of the execution (including the hidden window parameters stripped by the child process), we interrogate the persistent shell history provider:

```powershell
Get-Content (Get-PSReadLineOption).HistorySavePath -Tail 5 | sort -desc
```
This commands successfully recovers the unadulterated `Start-Process` string directly from the local profile database (`ConsoleHost_history.txt`).

---

## ⚡ Phase 3: Mitigation & Incident Response (IR)
Once the rogue PID (Process Identifier) is isolated and confirmed malicious, an authoritative termination directive is dispatched via the administrative shell to purge the threat vector from the computing environment.

### Remediation Command:
```powershell
Stop-Process -Id <TARGET_PID> -Force
```
### Post-Remediation Verification:
Querying the local subsystem verification filter validates successful evacuation of the malicious thread:
```powershell
Get-Process cmd
```
*Output Expected:* `Get-Process : Cannot find a process with the name "cmd".`
