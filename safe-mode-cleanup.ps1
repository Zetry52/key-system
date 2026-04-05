$ErrorActionPreference = 'Continue'

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$logPath = Join-Path $scriptDir ("safe-mode-cleanup-{0}.log" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))

function Write-Log {
    param([string]$Message)
    $line = "[{0}] {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Message
    $line | Tee-Object -FilePath $logPath -Append
}

function Set-RegistryString {
    param(
        [string]$Path,
        [string]$Name,
        [string]$Value
    )

    try {
        if (-not (Test-Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
        }

        New-ItemProperty -Path $Path -Name $Name -PropertyType String -Value $Value -Force | Out-Null
        Write-Log "OK set $Path\$Name = $Value"
    } catch {
        Write-Log "WARN set $Path\$Name :: $($_.Exception.Message)"
    }
}

function Remove-RegistryValue {
    param(
        [string]$Path,
        [string]$Name
    )

    try {
        if (Test-Path $Path) {
            Remove-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
            Write-Log "OK removed $Path\$Name"
        } else {
            Write-Log "Path not found: $Path"
        }
    } catch {
        Write-Log "WARN remove $Path\$Name :: $($_.Exception.Message)"
    }
}

function Remove-TaskCom {
    param([string]$FolderPath, [string]$TaskName)
    try {
        $svc = New-Object -ComObject 'Schedule.Service'
        $svc.Connect()
        $folder = $svc.GetFolder($FolderPath)
        $folder.DeleteTask($TaskName, 0)
        Write-Log "Deleted task via COM: $FolderPath$TaskName"
    } catch {
        Write-Log "WARN COM delete failed for $FolderPath$TaskName :: $($_.Exception.Message)"
    }
}

function Remove-TaskCacheEntry {
    param([string]$FolderName, [string]$TaskName)

    $base = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache'
    $treeKey = Join-Path (Join-Path $base 'Tree\Microsoft\Windows') (Join-Path $FolderName $TaskName)

    if (-not (Test-Path $treeKey)) {
        Write-Log "TaskCache tree key not found: $treeKey"
        return
    }

    try {
        $id = (Get-ItemProperty -Path $treeKey -Name Id -ErrorAction Stop).Id
        $id = ($id.ToString() -replace "`0", '').Trim()
        Write-Log "TaskCache id for $FolderName\\$TaskName = $id"
    } catch {
        Write-Log "WARN cannot read TaskCache Id for $FolderName\\$TaskName :: $($_.Exception.Message)"
        return
    }

    foreach ($root in 'Tasks','Plain','Boot','Logon','Maintenance','Idle','Time','Calendar','Event') {
        $key = Join-Path (Join-Path $base $root) $id
        if (Test-Path $key) {
            try {
                Remove-Item -Path $key -Recurse -Force -ErrorAction Stop
                Write-Log "Removed TaskCache key: $key"
            } catch {
                Write-Log "WARN failed to remove TaskCache key $key :: $($_.Exception.Message)"
            }
        }
    }

    try {
        Remove-Item -Path $treeKey -Recurse -Force -ErrorAction Stop
        Write-Log "Removed TaskCache tree key: $treeKey"
    } catch {
        Write-Log "WARN failed to remove TaskCache tree key $treeKey :: $($_.Exception.Message)"
    }
}

function Remove-PathForce {
    param([string]$Path)

    if (-not (Test-Path $Path)) {
        Write-Log "Path not found: $Path"
        return
    }

    cmd.exe /c "takeown /F `"$Path`" /A /R /D Y" | Out-Null
    cmd.exe /c "icacls `"$Path`" /grant *S-1-5-32-544:F /T /C" | Out-Null

    try {
        Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
        Write-Log "Removed path: $Path"
    } catch {
        Write-Log "WARN failed to remove path $Path :: $($_.Exception.Message)"
    }
}

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Run this script as Administrator."
    exit 1
}

Write-Log "Started as $([Security.Principal.WindowsIdentity]::GetCurrent().Name)"

$tasks = @(
    @{ Folder = 'WindowsBackup'; FolderPath = '\Microsoft\Windows\WindowsBackup\'; Name = 'CashClean'; File = 'C:\Windows\System32\Tasks\Microsoft\Windows\WindowsBackup\CashClean' },
    @{ Folder = 'WindowsBackup'; FolderPath = '\Microsoft\Windows\WindowsBackup\'; Name = 'OnlogonCheck'; File = 'C:\Windows\System32\Tasks\Microsoft\Windows\WindowsBackup\OnlogonCheck' },
    @{ Folder = 'WindowsBackup'; FolderPath = '\Microsoft\Windows\WindowsBackup\'; Name = 'ServiceManager'; File = 'C:\Windows\System32\Tasks\Microsoft\Windows\WindowsBackup\ServiceManager' },
    @{ Folder = 'WindowsBackup'; FolderPath = '\Microsoft\Windows\WindowsBackup\'; Name = 'WinlogonCheck'; File = 'C:\Windows\System32\Tasks\Microsoft\Windows\WindowsBackup\WinlogonCheck' },
    @{ Folder = 'WindowsBackup'; FolderPath = '\Microsoft\Windows\WindowsBackup\'; Name = 'CreedMobe'; File = 'C:\Windows\System32\Tasks\Microsoft\Windows\WindowsBackup\CreedMobe' },
    @{ Folder = 'CreedMobeQ'; FolderPath = '\Microsoft\Windows\CreedMobeQ\'; Name = 'RecoveryHosts'; File = 'C:\Windows\System32\Tasks\Microsoft\Windows\CreedMobeQ\RecoveryHosts' }
)

Write-Log 'Repairing Winlogon and policies'
Set-RegistryString 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'Shell' 'explorer.exe'
Set-RegistryString 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'Userinit' 'C:\Windows\system32\userinit.exe,'
Remove-RegistryValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' 'Realtek HD Audio'
Remove-RegistryValue 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' 'Realtek HD Audio'
Remove-RegistryValue 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System' 'DisableTaskMgr'
Remove-RegistryValue 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System' 'DisableTaskMgr'
Remove-RegistryValue 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System' 'DisableRegistryTools'
Remove-RegistryValue 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System' 'DisableRegistryTools'
Remove-RegistryValue 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System' 'DisableCMD'
Remove-RegistryValue 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System' 'DisableCMD'

Write-Log 'Removing suspicious scheduled tasks'
foreach ($task in $tasks) {
    $fullName = '\Microsoft\Windows\' + $task.Folder + '\' + $task.Name
    & schtasks.exe /End /TN $fullName /F 2>$null | Out-Null
    & schtasks.exe /Delete /TN $fullName /F 2>$null | Out-Null
    Remove-TaskCom -FolderPath $task.FolderPath -TaskName $task.Name
    Remove-TaskCacheEntry -FolderName $task.Folder -TaskName $task.Name
    Remove-PathForce -Path $task.File
}

Write-Log 'Removing suspicious folders'
foreach ($path in 'C:\ProgramData\ReaItekHD', 'C:\ProgramData\RealtekHD') {
    Remove-PathForce -Path $path
}

Write-Log 'Removing suspicious files under ProgramData'
$suspiciousItems = Get-ChildItem 'C:\ProgramData' -Force -Recurse -ErrorAction SilentlyContinue |
    Where-Object {
        $_.FullName -match 'CreedMobeQ|CreedMobe.*\.bat$|taskhostw?\.exe|ReaItekHD|RealtekHD'
    } |
    Sort-Object FullName -Descending

foreach ($item in $suspiciousItems) {
    if ($item.PSIsContainer) {
        Remove-PathForce -Path $item.FullName
    } else {
        Remove-PathForce -Path $item.FullName
    }
}

Write-Log 'Checking WMI persistence'
$rx = 'Creed|taskhost|MapData|ProgramData|ReaItek|Realtek'
try {
    Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding -ErrorAction Stop |
        Where-Object { $_.Filter -match $rx -or $_.Consumer -match $rx } |
        ForEach-Object {
            $_.Delete() | Out-Null
            Write-Log "Removed WMI binding: $($_.Filter) -> $($_.Consumer)"
        }

    Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer -ErrorAction Stop |
        Where-Object { $_.Name -match $rx -or $_.ExecutablePath -match $rx -or $_.CommandLineTemplate -match $rx } |
        ForEach-Object {
            $name = $_.Name
            $_.Delete() | Out-Null
            Write-Log "Removed WMI command consumer: $name"
        }

    Get-WmiObject -Namespace root\subscription -Class ActiveScriptEventConsumer -ErrorAction Stop |
        Where-Object { $_.Name -match $rx -or $_.ScriptText -match $rx } |
        ForEach-Object {
            $name = $_.Name
            $_.Delete() | Out-Null
            Write-Log "Removed WMI script consumer: $name"
        }

    Get-WmiObject -Namespace root\subscription -Class __EventFilter -ErrorAction Stop |
        Where-Object { $_.Name -match $rx -or $_.Query -match $rx } |
        ForEach-Object {
            $name = $_.Name
            $_.Delete() | Out-Null
            Write-Log "Removed WMI event filter: $name"
        }
} catch {
    Write-Log "WARN WMI cleanup failed :: $($_.Exception.Message)"
}

Write-Log 'Final verification'
foreach ($task in $tasks) {
    $fullName = '\Microsoft\Windows\' + $task.Folder + '\' + $task.Name
    $result = & schtasks.exe /Query /TN $fullName 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Log "STILL_PRESENT task: $fullName"
    } else {
        Write-Log "OK task missing: $fullName"
    }
}

Write-Log 'Finished. If TaskCache or files still show access denied, run winre-offline-clean.cmd from WinRE.'
