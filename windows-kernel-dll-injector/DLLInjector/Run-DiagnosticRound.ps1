param(
    [ValidateSet("Arm", "Collect")]
    [string]$Mode = "Arm",
    [string]$DllPath,
    [UInt64]$TargetPid,
    [string]$InjectorExe = (Join-Path $PSScriptRoot "x64\\Release\\DLLInjectorCom.exe"),
    [string]$OutputRoot = (Join-Path $PSScriptRoot "artifacts"),
    [string]$OutputDir,
    [string]$TaskName = "DLLInjectorDiagnosticRound"
)

$ErrorActionPreference = "Stop"

function Ensure-Directory {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run this script from an elevated PowerShell session."
    }
}

function Write-TextFile {
    param(
        [string]$Path,
        [string[]]$Lines
    )

    $Lines | Out-File -LiteralPath $Path -Encoding ascii
}

function Save-CommandOutput {
    param(
        [string]$Path,
        [scriptblock]$Command
    )

    try {
        & $Command | Out-File -LiteralPath $Path -Encoding ascii
    }
    catch {
        $_ | Out-File -LiteralPath $Path -Encoding ascii
    }
}

function Enable-LocalDump {
    param(
        [string]$ProcessName,
        [string]$DumpFolder
    )

    $keyPath = "HKLM:\\SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting\\LocalDumps\\$ProcessName"
    New-Item -Path $keyPath -Force | Out-Null
    New-ItemProperty -Path $keyPath -Name DumpFolder -Value $DumpFolder -PropertyType ExpandString -Force | Out-Null
    New-ItemProperty -Path $keyPath -Name DumpCount -Value 5 -PropertyType DWord -Force | Out-Null
    New-ItemProperty -Path $keyPath -Name DumpType -Value 2 -PropertyType DWord -Force | Out-Null
}

function Register-CollectorTask {
    param(
        [string]$Name,
        [string]$ScriptPath,
        [string]$BundlePath
    )

    $argument = "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`" -Mode Collect -OutputDir `"$BundlePath`" -TaskName `"$Name`""
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $argument
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    Register-ScheduledTask -TaskName $Name -Action $action -Trigger $trigger -RunLevel Highest -Force | Out-Null
}

function Copy-RecentCrashDumps {
    param([string]$DumpDir)

    $localCrashDumps = Join-Path $env:LOCALAPPDATA "CrashDumps"
    if (Test-Path -LiteralPath $localCrashDumps) {
        $localDumps = Get-ChildItem -LiteralPath $localCrashDumps -Filter "*.dmp" -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match "^(cmd|explorer).*\\.dmp$" } |
            Sort-Object LastWriteTime -Descending |
            Select-Object -First 6

        foreach ($dump in $localDumps) {
            try {
                Copy-Item -LiteralPath $dump.FullName -Destination $DumpDir -Force -ErrorAction Stop
            }
            catch {
            }
        }
    }

    $minidumpDir = "C:\\Windows\\Minidump"
    if (Test-Path -LiteralPath $minidumpDir) {
        $miniDumps = Get-ChildItem -LiteralPath $minidumpDir -Filter "*.dmp" -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending |
            Select-Object -First 3

        foreach ($dump in $miniDumps) {
            try {
                Copy-Item -LiteralPath $dump.FullName -Destination $DumpDir -Force -ErrorAction Stop
            }
            catch {
            }
        }
    }
}

function Copy-RecentWerReports {
    param([string]$DumpDir)

    $reportArchive = Join-Path $env:ProgramData "Microsoft\\Windows\\WER\\ReportArchive"
    if (-not (Test-Path -LiteralPath $reportArchive)) {
        return
    }

    $targets = Get-ChildItem -LiteralPath $reportArchive -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match "(cmd|explorer)\\.exe" } |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 4

    foreach ($target in $targets) {
        $destination = Join-Path $DumpDir $target.Name
        try {
            Copy-Item -LiteralPath $target.FullName -Destination $destination -Recurse -Force -ErrorAction Stop
        }
        catch {
        }
    }
}

function Collect-Artifacts {
    param(
        [string]$BundlePath,
        [string]$Name
    )

    Ensure-Directory $BundlePath

    $eventsDir = Join-Path $BundlePath "events"
    $dumpsDir = Join-Path $BundlePath "dumps"
    Ensure-Directory $eventsDir
    Ensure-Directory $dumpsDir

    $windowStart = (Get-Date).AddHours(-24)

    Get-WinEvent -FilterHashtable @{ LogName = "Application"; Id = 1000; StartTime = $windowStart } -ErrorAction SilentlyContinue |
        Where-Object { $_.Message -match "explorer\\.exe|cmd\\.exe" } |
        Export-Csv -LiteralPath (Join-Path $eventsDir "application_errors.csv") -NoTypeInformation

    Get-WinEvent -FilterHashtable @{ LogName = "System"; Id = 41, 1001; StartTime = $windowStart } -ErrorAction SilentlyContinue |
        Export-Csv -LiteralPath (Join-Path $eventsDir "system_bugcheck_events.csv") -NoTypeInformation

    Get-WinEvent -FilterHashtable @{ LogName = "Application"; ProviderName = "Windows Error Reporting"; StartTime = $windowStart } -ErrorAction SilentlyContinue |
        Where-Object { $_.Message -match "explorer\\.exe|cmd\\.exe" } |
        Export-Csv -LiteralPath (Join-Path $eventsDir "wer_events.csv") -NoTypeInformation

    Copy-RecentCrashDumps -DumpDir $dumpsDir
    Copy-RecentWerReports -DumpDir $dumpsDir

    $memoryDump = Get-Item -LiteralPath "C:\\Windows\\MEMORY.DMP" -ErrorAction SilentlyContinue
    if ($memoryDump) {
        Save-CommandOutput -Path (Join-Path $dumpsDir "memory_dump.txt") -Command {
            Get-Item -LiteralPath "C:\\Windows\\MEMORY.DMP" | Format-List FullName, Length, LastWriteTime
        }
    }

    Save-CommandOutput -Path (Join-Path $BundlePath "driver_service.txt") -Command { sc.exe qc DLLInjector }
    Save-CommandOutput -Path (Join-Path $BundlePath "crash_control.txt") -Command {
        Get-ItemProperty "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\CrashControl" | Format-List *
    }

    Write-TextFile -Path (Join-Path $BundlePath "README.txt") -Lines @(
        "Bundle: $BundlePath",
        "Injector diagnostic snapshot: injector_diag.txt",
        "Explorer/cmd crash dumps: dumps\\",
        "Kernel crash evidence: dumps\\memory_dump.txt and dumps\\*.dmp",
        "Event log extracts: events\\"
    )

    if ($Name) {
        Unregister-ScheduledTask -TaskName $Name -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
    }
}

if ($Mode -eq "Collect") {
    if (-not $OutputDir) {
        throw "Collect mode requires -OutputDir."
    }

    Collect-Artifacts -BundlePath $OutputDir -Name $TaskName
    return
}

Assert-Administrator
Ensure-Directory $OutputRoot

if (-not $OutputDir) {
    $OutputDir = Join-Path $OutputRoot ("round_" + (Get-Date -Format "yyyyMMdd_HHmmss"))
}

Ensure-Directory $OutputDir
Ensure-Directory (Join-Path $OutputDir "dumps")

Register-CollectorTask -Name $TaskName -ScriptPath $PSCommandPath -BundlePath $OutputDir

Enable-LocalDump -ProcessName "cmd.exe" -DumpFolder (Join-Path $OutputDir "dumps")
Enable-LocalDump -ProcessName "explorer.exe" -DumpFolder (Join-Path $OutputDir "dumps")

New-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\CrashControl" -Name CrashDumpEnabled -Value 2 -PropertyType DWord -Force | Out-Null
New-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\CrashControl" -Name AlwaysKeepMemoryDump -Value 1 -PropertyType DWord -Force | Out-Null
New-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\CrashControl" -Name LogEvent -Value 1 -PropertyType DWord -Force | Out-Null
New-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\CrashControl" -Name Overwrite -Value 1 -PropertyType DWord -Force | Out-Null

Save-CommandOutput -Path (Join-Path $OutputDir "systeminfo.txt") -Command { systeminfo.exe }
Save-CommandOutput -Path (Join-Path $OutputDir "bcdedit.txt") -Command { bcdedit.exe /enum }
Save-CommandOutput -Path (Join-Path $OutputDir "driver_query.txt") -Command { driverquery.exe /v }
Save-CommandOutput -Path (Join-Path $OutputDir "driver_service.txt") -Command { sc.exe qc DLLInjector }

if ($DllPath -and $TargetPid) {
    if (-not (Test-Path -LiteralPath $InjectorExe)) {
        throw "Injector executable not found: $InjectorExe"
    }

    & $InjectorExe $DllPath $TargetPid (Join-Path $OutputDir "injector_diag.txt") 2>&1 |
        Tee-Object -FilePath (Join-Path $OutputDir "injector_console.txt")
}

Write-TextFile -Path (Join-Path $OutputDir "NEXT_STEPS.txt") -Lines @(
    "Reproduce the problem once.",
    "If the system bugchecks, sign back in once and the scheduled task '$TaskName' will collect the dumps and events.",
    "The injector snapshot is written to injector_diag.txt when the user-mode tool runs."
)

Write-Output "Diagnostic round armed. Output folder: $OutputDir"
