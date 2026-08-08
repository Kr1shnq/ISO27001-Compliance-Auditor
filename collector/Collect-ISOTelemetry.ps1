

[CmdletBinding()]
param(
    [string] $OutputPath = ".",
    [ValidateSet("Json", "Csv", "Both")]
    [string] $Format = "Both",
    [switch] $IncludeAttestations,
    [string] $ApprovedSoftware,
    [switch] $Quiet
)

$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference    = 'SilentlyContinue'
$CollectorVersion      = '1.0.0'

# =============================================================================
# Helpers
# =============================================================================

function Write-Step {
    param([string] $Message)
    if (-not $Quiet) { Write-Host "  [*] $Message" -ForegroundColor DarkCyan }
}

function Write-Ok {
    param([string] $Message)
    if (-not $Quiet) { Write-Host "  [+] $Message" -ForegroundColor Green }
}

function Write-Warn {
    param([string] $Message)
    if (-not $Quiet) { Write-Host "  [!] $Message" -ForegroundColor Yellow }
}

# Run a probe safely: return its value, or $null if anything at all goes wrong.
function Get-Safe {
    param([scriptblock] $Probe, $Default = $null)
    try {
        $v = & $Probe
        if ($null -eq $v) { return $Default }
        return $v
    } catch {
        return $Default
    }
}

function Test-Admin {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        return (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

# Read a registry value without throwing when the key is absent.
function Get-Reg {
    param([string] $Path, [string] $Name, $Default = $null)
    try {
        $item = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
        if ($null -ne $item.$Name) { return $item.$Name }
        return $Default
    } catch { return $Default }
}

# Parse the fixed-format output of `net accounts`.
function Get-NetAccounts {
    $out = @{}
    try {
        $lines = net accounts 2>$null
        foreach ($line in $lines) {
            if ($line -match '^(.*?):\s+(.*)$') {
                $out[$matches[1].Trim()] = $matches[2].Trim()
            }
        }
    } catch { }
    return $out
}

function ConvertTo-IntOrNull {
    param($Value)
    if ($null -eq $Value) { return $null }
    $s = "$Value".Trim()
    if ($s -match '^\d+$') { return [int]$s }
    if ($s -match 'Never|Unlimited|None') { return 0 }
    return $null
}

# Map an auditpol subcategory to its "Success", "Failure", "Success and Failure" setting.
function Get-AuditSetting {
    param([string] $Subcategory)
    try {
        $raw = auditpol /get /subcategory:"$Subcategory" /r 2>$null | ConvertFrom-Csv
        if ($raw -and $raw[0].'Inclusion Setting') { return $raw[0].'Inclusion Setting' }
    } catch { }
    return $null
}

$isAdmin = Test-Admin

if (-not $Quiet) {
    Write-Host ""
    Write-Host "===============================================================" -ForegroundColor Cyan
    Write-Host "  ISO 27001 Compliance Auditor - Telemetry Collector v$CollectorVersion" -ForegroundColor Cyan
    Write-Host "  Read-only configuration inventory for Annex A gap analysis" -ForegroundColor Gray
    Write-Host "===============================================================" -ForegroundColor Cyan
    Write-Host ""
    if ($isAdmin) { Write-Ok "Running elevated - full telemetry available" }
    else { Write-Warn "NOT running as Administrator - BitLocker, audit policy, Defender and firewall data will be incomplete" }
    Write-Host ""
}

# =============================================================================
# 1. Metadata
# =============================================================================
Write-Step "Collecting system metadata"

$os  = Get-Safe { Get-CimInstance Win32_OperatingSystem }
$cs  = Get-Safe { Get-CimInstance Win32_ComputerSystem }
$bios= Get-Safe { Get-CimInstance Win32_BIOS }

$metadata = [ordered]@{
    hostname          = $env:COMPUTERNAME
    fqdn              = Get-Safe { [System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName }
    os_caption        = Get-Safe { $os.Caption }
    os_version        = Get-Safe { $os.Version }
    os_build          = Get-Safe { (Get-Reg 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' 'DisplayVersion') }
    os_install_date   = Get-Safe { $os.InstallDate.ToString('yyyy-MM-dd') }
    last_boot_utc     = Get-Safe { $os.LastBootUpTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }
    is_server         = Get-Safe { $os.ProductType -ne 1 }
    domain            = Get-Safe { $cs.Domain }
    domain_joined     = Get-Safe { [bool]$cs.PartOfDomain }
    manufacturer      = Get-Safe { $cs.Manufacturer }
    model             = Get-Safe { $cs.Model }
    serial_number     = Get-Safe { $bios.SerialNumber }
    collected_utc     = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    collector_version = $CollectorVersion
    collected_elevated= $isAdmin
    collected_by      = "$env:USERDOMAIN\$env:USERNAME"
}

# =============================================================================
# 2. Identity and access management  ->  A.5.15-A.5.18, A.8.2, A.8.5
# =============================================================================
Write-Step "Collecting identity, password policy and privileged access"

$netAcc     = Get-NetAccounts
$localUsers = Get-Safe { Get-LocalUser } @()
$adminGroup = Get-Safe {
    (Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop)
} @()

# MFA is not a native local Windows setting. It is inferred from the presence of a
# credential provider / passwordless technology. Override via -Attestation if you use a
# third-party MFA product this heuristic cannot see.
$hello    = Get-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork' 'Enabled'
$smartcard= Get-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{8FD7E19C-3BF7-489B-A72C-846AB3678C96}' 'Disabled'
$duo      = Get-Safe { Test-Path 'HKLM:\SOFTWARE\Duo Security' } $false
$mfaHints = @()
if ($hello -eq 1)            { $mfaHints += 'WindowsHelloForBusiness' }
if ($smartcard -ne 1 -and $null -ne $smartcard) { $mfaHints += 'SmartCard' }
if ($duo)                    { $mfaHints += 'DuoSecurity' }
if (Get-Safe { Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify\AzureADPasswordProtection' } $false) {
    $mfaHints += 'EntraIDPasswordProtection'
}

$inactiveCutoff = (Get-Date).AddDays(-90)

$identity = [ordered]@{
    mfa_enabled                     = ($mfaHints.Count -gt 0)
    mfa_providers                   = $mfaHints
    mfa_coverage_pct                = $(if ($mfaHints.Count -gt 0) { 100 } else { 0 })
    local_user_count                = Get-Safe { ($localUsers | Where-Object Enabled).Count }
    local_admin_count               = Get-Safe { ($adminGroup | Measure-Object).Count }
    local_admin_members             = Get-Safe { @($adminGroup | ForEach-Object { $_.Name }) } @()
    guest_account_enabled           = Get-Safe { [bool](Get-LocalUser -Name 'Guest').Enabled } $false
    default_admin_renamed           = Get-Safe {
        $a = Get-LocalUser | Where-Object { $_.SID.Value -like '*-500' }
        ($a -and $a.Name -ne 'Administrator')
    }
    password_min_length             = ConvertTo-IntOrNull $netAcc['Minimum password length']
    password_max_age_days           = ConvertTo-IntOrNull $netAcc['Maximum password age (days)']
    password_min_age_days           = ConvertTo-IntOrNull $netAcc['Minimum password age (days)']
    password_history_size           = ConvertTo-IntOrNull $netAcc['Length of password history maintained']
    lockout_threshold               = ConvertTo-IntOrNull $netAcc['Lockout threshold']
    lockout_duration_min            = ConvertTo-IntOrNull $netAcc['Lockout duration (minutes)']
    lockout_window_min              = ConvertTo-IntOrNull $netAcc['Lockout observation window (minutes)']
    password_complexity_enabled     = Get-Safe {
        $tmp = Join-Path $env:TEMP "secpol_$([guid]::NewGuid().ToString('N')).cfg"
        secedit /export /cfg $tmp /areas SECURITYPOLICY | Out-Null
        $val = (Select-String -Path $tmp -Pattern 'PasswordComplexity' |
                Select-Object -First 1) -replace '.*=\s*', ''
        Remove-Item $tmp -Force -ErrorAction SilentlyContinue
        ([int]"$val".Trim() -eq 1)
    }
    accounts_password_never_expires = Get-Safe {
        ($localUsers | Where-Object { $_.Enabled -and $_.PasswordNeverExpires }).Count
    }
    inactive_accounts_90d           = Get-Safe {
        ($localUsers | Where-Object {
            $_.Enabled -and $_.LastLogon -and $_.LastLogon -lt $inactiveCutoff
        }).Count
    }
    blank_password_accounts         = Get-Safe {
        ($localUsers | Where-Object { $_.Enabled -and -not $_.PasswordRequired }).Count
    }
    laps_enabled                    = Get-Safe {
        [bool]((Get-Reg 'HKLM:\SOFTWARE\Microsoft\Policies\LAPS' 'BackupDirectory') -or
               (Get-Reg 'HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd' 'AdmPwdEnabled') -eq 1)
    } $false
    credential_guard_enabled        = Get-Safe {
        $dg = Get-CimInstance -ClassName Win32_DeviceGuard `
              -Namespace 'root\Microsoft\Windows\DeviceGuard' -ErrorAction Stop
        ($dg.SecurityServicesRunning -contains 1)
    }
    standard_users_cannot_install   = Get-Safe {
        (Get-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' 'DisableMSI') -in @(1, 2)
    } $false
    logon_banner_configured         = Get-Safe {
        -not [string]::IsNullOrWhiteSpace(
            (Get-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'legalnoticetext'))
    } $false
}

# =============================================================================
# 3. Encryption and cryptography  ->  A.5.14, A.7.9, A.8.24
# =============================================================================
Write-Step "Collecting encryption and cryptographic configuration"

$bitlocker = Get-Safe { Get-BitLockerVolume -ErrorAction Stop } @()
$osVol     = $bitlocker | Where-Object { $_.VolumeType -eq 'OperatingSystem' } | Select-Object -First 1

function Get-SchannelProtocol {
    param([string] $Name)
    # Returns $true when the client-side protocol is enabled (default when unset).
    $base = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Name\Client"
    $enabled  = Get-Reg $base 'Enabled'
    $disabled = Get-Reg $base 'DisabledByDefault'
    if ($null -eq $enabled -and $null -eq $disabled) {
        # Unset: TLS 1.0/1.1 default on for legacy OS, TLS 1.2+ default on everywhere.
        return $true
    }
    if ($enabled -eq 0) { return $false }
    if ($enabled -ge 1) { return $true }
    return ($disabled -eq 0)
}

$encryption = [ordered]@{
    disk_encryption_enabled  = Get-Safe {
        ($null -ne $osVol) -and ($osVol.ProtectionStatus -eq 'On')
    }
    disk_encryption_type     = Get-Safe {
        if ($osVol -and $osVol.EncryptionMethod -and "$($osVol.EncryptionMethod)" -ne 'None') {
            "$($osVol.EncryptionMethod)"
        } else { 'None' }
    }
    encryption_percentage    = Get-Safe { [int]$osVol.EncryptionPercentage }
    key_protector_present    = Get-Safe { ($osVol.KeyProtector | Measure-Object).Count -gt 0 }
    key_protector_types      = Get-Safe {
        @($osVol.KeyProtector | ForEach-Object { "$($_.KeyProtectorType)" })
    } @()
    recovery_key_escrowed    = Get-Safe {
        [bool](Get-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' 'OSActiveDirectoryBackup')
    } $false
    # NOTE: a companion *_count is emitted for every list the audit engine tests
    # against. Windows PowerShell 5.1 serialises an empty array as "" rather than
    # [], which would turn a clean result into "no data". The integer count is
    # unambiguous in both JSON and CSV, so the baseline checks that instead.
    unencrypted_volumes      = Get-Safe {
        @($bitlocker | Where-Object {
            $_.VolumeType -eq 'Data' -and $_.ProtectionStatus -ne 'On'
        } | ForEach-Object { $_.MountPoint })
    } @()
    unencrypted_volume_count = Get-Safe {
        @($bitlocker | Where-Object {
            $_.VolumeType -eq 'Data' -and $_.ProtectionStatus -ne 'On'
        }).Count
    } 0
    removable_drive_encryption_required = Get-Safe {
        (Get-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' 'RDVDenyWriteAccess') -eq 1
    } $false
    tls10_enabled            = Get-SchannelProtocol 'TLS 1.0'
    tls11_enabled            = Get-SchannelProtocol 'TLS 1.1'
    tls12_enabled            = Get-SchannelProtocol 'TLS 1.2'
    tls13_enabled            = Get-SchannelProtocol 'TLS 1.3'
    ssl30_enabled            = Get-SchannelProtocol 'SSL 3.0'
    smb_signing_required     = Get-Safe {
        (Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'RequireSecuritySignature') -eq 1
    } $false
    smbv1_enabled            = Get-Safe {
        $f = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction Stop
        ($f.State -eq 'Enabled')
    }
    fips_mode                = Get-Safe {
        (Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy' 'Enabled') -eq 1
    } $false
}

# =============================================================================
# 4. Logging and audit policy  ->  A.5.28, A.8.15-A.8.17
# =============================================================================
Write-Step "Collecting logging and audit policy"

$secLog = Get-Safe { Get-WinEvent -ListLog Security -ErrorAction Stop }

$auditMap = [ordered]@{
    audit_logon_events       = 'Logon'
    audit_logoff_events      = 'Logoff'
    audit_account_lockout    = 'Account Lockout'
    audit_object_access      = 'File System'
    audit_policy_change      = 'Audit Policy Change'
    audit_privilege_use      = 'Sensitive Privilege Use'
    audit_account_management = 'User Account Management'
    audit_process_creation   = 'Process Creation'
}

$logging = [ordered]@{}
foreach ($k in $auditMap.Keys) {
    $logging[$k] = if ($isAdmin) { Get-AuditSetting $auditMap[$k] } else { $null }
}

$enabledAudits = @($logging.Values | Where-Object { $_ -and $_ -ne 'No Auditing' }).Count
$logging['logging_level'] = switch ($enabledAudits) {
    { $_ -ge 7 } { 'Verbose'; break }
    { $_ -ge 4 } { 'Standard'; break }
    { $_ -ge 1 } { 'Minimal'; break }
    default      { if ($isAdmin) { 'None' } else { $null } }
}

$logging['security_log_max_size_mb']      = Get-Safe { [int]($secLog.MaximumSizeInBytes / 1MB) }
$logging['security_log_retention_days']   = Get-Safe {
    # Prefer an explicit retention policy; otherwise estimate from the oldest record held.
    $explicit = Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security' 'RetentionDays'
    if ($null -ne $explicit -and $explicit -gt 0) { return [int]$explicit }
    $oldest = (Get-WinEvent -LogName Security -Oldest -MaxEvents 1 -ErrorAction Stop).TimeCreated
    [int]((Get-Date) - $oldest).TotalDays
}
$logging['security_log_record_count']     = Get-Safe { [int64]$secLog.RecordCount }
$logging['powershell_scriptblock_logging']= Get-Safe {
    (Get-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging') -eq 1
} $false
$logging['powershell_module_logging']     = Get-Safe {
    (Get-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' 'EnableModuleLogging') -eq 1
} $false
$logging['command_line_auditing']         = Get-Safe {
    (Get-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' 'ProcessCreationIncludeCmdLine_Enabled') -eq 1
} $false
$logging['log_forwarding_enabled']        = Get-Safe {
    $wef = Get-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager' '1'
    $siem = @('splunkforwarder','MMAExtensionHealthManager','HealthService','nxlog','datadog-agent','WazuhSvc','elastic-agent') |
            Where-Object { Get-Service -Name $_ -ErrorAction SilentlyContinue }
    [bool]($wef -or $siem)
} $false
$logging['siem_agents_detected']          = Get-Safe {
    @(@('splunkforwarder','HealthService','nxlog','datadog-agent','WazuhSvc','elastic-agent','MDE.Windows') |
      Where-Object { Get-Service -Name $_ -ErrorAction SilentlyContinue })
} @()

# Clock synchronisation
$w32 = Get-Safe { w32tm /query /status 2>$null }
$logging['time_sync_configured'] = Get-Safe {
    (Get-Service W32Time -ErrorAction Stop).Status -eq 'Running'
} $false
$logging['ntp_server'] = Get-Safe {
    $src = w32tm /query /source 2>$null
    if ($src -and $src -notmatch 'Local CMOS Clock|error') { "$src".Trim() } else { $null }
}
$logging['time_offset_seconds'] = Get-Safe {
    $line = $w32 | Select-String 'Phase Offset'
    if ($line) {
        $v = ($line -replace '.*:\s*', '') -replace 's\s*$', ''
        [math]::Abs([double]$v)
    } else { $null }
}

# =============================================================================
# 5. Endpoint protection  ->  A.8.1, A.8.7, A.8.12, A.8.16, A.8.18, A.8.20, A.8.23
# =============================================================================
Write-Step "Collecting endpoint protection and hardening state"

$mpStatus = Get-Safe { Get-MpComputerStatus -ErrorAction Stop }
$mpPref   = Get-Safe { Get-MpPreference -ErrorAction Stop }
$avProd   = Get-Safe {
    Get-CimInstance -Namespace 'root\SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction Stop
}
$fw       = Get-Safe { Get-NetFirewallProfile -ErrorAction Stop } @()

$endpoint = [ordered]@{
    antivirus_enabled          = Get-Safe {
        [bool]($mpStatus.AntivirusEnabled -or ($avProd | Measure-Object).Count -gt 0)
    }
    antivirus_product          = Get-Safe {
        if ($avProd) { ($avProd | Select-Object -First 1).displayName }
        elseif ($mpStatus) { 'Microsoft Defender Antivirus' } else { $null }
    }
    realtime_protection        = Get-Safe { [bool]$mpStatus.RealTimeProtectionEnabled }
    behavior_monitoring        = Get-Safe { [bool]$mpStatus.BehaviorMonitorEnabled }
    signature_age_days         = Get-Safe { [int]$mpStatus.AntivirusSignatureAge }
    signature_version          = Get-Safe { "$($mpStatus.AntivirusSignatureVersion)" }
    last_full_scan_days        = Get-Safe { [int]$mpStatus.FullScanAge }
    tamper_protection          = Get-Safe { [bool]$mpStatus.IsTamperProtected }
    cloud_protection_enabled   = Get-Safe { $mpPref.MAPSReporting -ne 0 }
    network_protection_enabled = Get-Safe { $mpPref.EnableNetworkProtection -eq 1 }
    pua_protection_enabled     = Get-Safe { $mpPref.PUAProtection -eq 1 }
    asr_rules_enabled          = Get-Safe {
        @($mpPref.AttackSurfaceReductionRules_Actions | Where-Object { $_ -eq 1 }).Count
    } 0
    edr_enabled                = Get-Safe {
        [bool]((Get-Service Sense -ErrorAction SilentlyContinue) -or
               (Get-Service CSFalconService, CbDefense, SentinelAgent, cyserver -ErrorAction SilentlyContinue))
    } $false
    firewall_domain            = Get-Safe {
        [bool]($fw | Where-Object Name -eq 'Domain').Enabled
    }
    firewall_private           = Get-Safe {
        [bool]($fw | Where-Object Name -eq 'Private').Enabled
    }
    firewall_public            = Get-Safe {
        [bool]($fw | Where-Object Name -eq 'Public').Enabled
    }
    inbound_default_block      = Get-Safe {
        @($fw | Where-Object { $_.DefaultInboundAction -eq 'Block' }).Count -ge 3
    }
    firewall_rule_count        = Get-Safe { (Get-NetFirewallRule -Enabled True -ErrorAction Stop | Measure-Object).Count }
    secure_boot_enabled        = Get-Safe { [bool](Confirm-SecureBootUEFI -ErrorAction Stop) }
    tpm_present                = Get-Safe { [bool](Get-Tpm -ErrorAction Stop).TpmPresent }
    tpm_ready                  = Get-Safe { [bool](Get-Tpm -ErrorAction Stop).TpmReady }
    tpm_version                = Get-Safe {
        (Get-CimInstance -Namespace 'root\CIMV2\Security\MicrosoftTpm' `
            -ClassName Win32_Tpm -ErrorAction Stop).SpecVersion -split ',' | Select-Object -First 1
    }
    uac_enabled                = Get-Safe {
        (Get-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA') -eq 1
    }
    applocker_or_wdac_enabled  = Get-Safe {
        $al = @(Get-AppLockerPolicy -Effective -ErrorAction Stop).RuleCollections |
              Where-Object { $_.EnforcementMode -eq 'Enabled' }
        $ci = (Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy' 'DeployConfigCIPolicy') -eq 1
        [bool](($al | Measure-Object).Count -gt 0 -or $ci)
    } $false
    usb_storage_blocked        = Get-Safe {
        ((Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR' 'Start') -eq 4) -or
        ((Get-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}' 'Deny_All') -eq 1)
    } $false
    screen_lock_timeout_min    = Get-Safe {
        $gpo  = Get-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'InactivityTimeoutSecs'
        $user = Get-Reg 'HKCU:\Control Panel\Desktop' 'ScreenSaveTimeOut'
        $secs = if ($gpo) { [int]$gpo } elseif ($user) { [int]$user } else { $null }
        if ($secs) { [int][math]::Round($secs / 60) } else { $null }
    }
    screensaver_password_required = Get-Safe {
        (Get-Reg 'HKCU:\Control Panel\Desktop' 'ScreenSaverIsSecure') -eq '1'
    } $false
}

# =============================================================================
# 6. Patching and vulnerability management  ->  A.8.8, A.5.36
# =============================================================================
Write-Step "Collecting patch and update state"

$hotfixes = Get-Safe { Get-HotFix | Sort-Object InstalledOn -Descending } @()

$patching = [ordered]@{
    auto_update_enabled       = Get-Safe {
        $au = Get-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update' 'AUOptions'
        $noAuto = Get-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' 'NoAutoUpdate'
        if ($noAuto -eq 1) { $false }
        elseif ($null -ne $au) { [int]$au -ge 3 }
        else { (Get-Service wuauserv -ErrorAction SilentlyContinue).StartType -ne 'Disabled' }
    }
    last_patch_install_days   = Get-Safe {
        $last = ($hotfixes | Where-Object InstalledOn | Select-Object -First 1).InstalledOn
        if ($last) { [int]((Get-Date) - $last).TotalDays } else { $null }
    }
    last_patch_kb             = Get-Safe { ($hotfixes | Select-Object -First 1).HotFixID }
    installed_patch_count     = Get-Safe { ($hotfixes | Measure-Object).Count }
    missing_critical_patches  = Get-Safe {
        $s = New-Object -ComObject Microsoft.Update.Session
        $r = $s.CreateUpdateSearcher().Search("IsInstalled=0 and Type='Software' and IsHidden=0")
        @($r.Updates | Where-Object {
            $_.MsrcSeverity -in @('Critical', 'Important') -or
            $_.Categories | Where-Object { $_.Name -match 'Security|Critical' }
        }).Count
    }
    pending_updates_total     = Get-Safe {
        $s = New-Object -ComObject Microsoft.Update.Session
        $s.CreateUpdateSearcher().Search("IsInstalled=0 and Type='Software' and IsHidden=0").Updates.Count
    }
    pending_reboot            = Get-Safe {
        [bool]((Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') -or
               (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') -or
               (Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' 'PendingFileRenameOperations'))
    } $false
    os_supported              = Get-Safe {
        # Coarse end-of-support check against known Windows build baselines.
        $build = [int]([Environment]::OSVersion.Version.Build)
        $caption = "$($os.Caption)"
        if     ($caption -match 'Windows 11')          { $true }
        elseif ($caption -match 'Windows 10')          { $build -ge 19045 }   # 22H2+
        elseif ($caption -match 'Server 2022|Server 2025') { $true }
        elseif ($caption -match 'Server 2019|Server 2016') { $true }
        elseif ($caption -match 'Windows 7|Windows 8|Server 2008|Server 2012') { $false }
        else   { $null }
    }
    wsus_server               = Get-Safe {
        Get-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' 'WUServer'
    }
}

# =============================================================================
# 7. Network exposure  ->  A.8.3, A.8.20-A.8.23
# =============================================================================
Write-Step "Collecting network exposure and services"

$listeners  = Get-Safe {
    Get-NetTCPConnection -State Listen -ErrorAction Stop |
        Select-Object -ExpandProperty LocalPort -Unique | Sort-Object
} @()
$riskyPorts = @(21, 23, 69, 135, 139, 445, 512, 513, 514, 1433, 3389, 5900)
$shares     = Get-Safe { Get-SmbShare -ErrorAction Stop | Where-Object { -not $_.Special } } @()

$network = [ordered]@{
    rdp_enabled                  = Get-Safe {
        (Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections') -eq 0
    }
    rdp_nla_required             = Get-Safe {
        (Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication') -eq 1
    }
    rdp_port                     = Get-Safe {
        [int](Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'PortNumber')
    }
    open_listening_ports         = @($listeners)
    listening_port_count         = @($listeners).Count
    risky_ports_open             = @($listeners | Where-Object { $riskyPorts -contains $_ })
    risky_ports_open_count       = @($listeners | Where-Object { $riskyPorts -contains $_ }).Count
    open_shares                  = Get-Safe { @($shares | ForEach-Object { $_.Name }) } @()
    open_shares_everyone         = Get-Safe {
        @($shares | ForEach-Object {
            Get-SmbShareAccess -Name $_.Name -ErrorAction SilentlyContinue
        } | Where-Object {
            $_.AccountName -match 'Everyone|ANONYMOUS' -and $_.AccessRight -ne 'Read'
        }).Count
    } 0
    anonymous_share_enumeration  = Get-Safe {
        (Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RestrictAnonymous') -ne 1
    }
    netbios_enabled              = Get-Safe {
        @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' |
          Where-Object { $_.TcpipNetbiosOptions -ne 2 }).Count -gt 0
    }
    llmnr_disabled               = Get-Safe {
        (Get-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast') -eq 0
    } $false
    ipv6_enabled                 = Get-Safe {
        [bool](Get-NetAdapterBinding -ComponentID ms_tcpip6 -ErrorAction Stop |
               Where-Object Enabled | Select-Object -First 1)
    }
    dns_servers                  = Get-Safe {
        @(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop |
          Where-Object { $_.ServerAddresses } |
          ForEach-Object { $_.ServerAddresses } | Select-Object -Unique)
    } @()
    dns_filtering_enabled        = Get-Safe {
        # Known protective-DNS resolvers, or an explicit DoH template.
        $known = @('1.1.1.2','1.0.0.2','9.9.9.9','149.112.112.112','208.67.222.123','185.228.168.9')
        $svrs  = @(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop |
                   ForEach-Object { $_.ServerAddresses })
        [bool](@($svrs | Where-Object { $known -contains $_ }).Count -gt 0)
    } $false
    vpn_configured               = Get-Safe {
        [bool](@(Get-VpnConnection -AllUserConnection -ErrorAction SilentlyContinue).Count +
               @(Get-VpnConnection -ErrorAction SilentlyContinue).Count -gt 0 -or
               @(Get-Service -Name 'CiscoSecureClient*','NetworkManager','ZSATunnel','GlobalProtect','WireGuardManager*' `
                 -ErrorAction SilentlyContinue).Count -gt 0)
    } $false
    host_firewall_isolation      = Get-Safe {
        @(Get-NetFirewallRule -Direction Inbound -Action Block -Enabled True -ErrorAction Stop).Count -gt 0
    } $false
    wifi_open_networks           = Get-Safe {
        @((netsh wlan show profiles) -match 'All User Profile' | ForEach-Object {
            $p = ($_ -split ':')[1].Trim()
            $d = netsh wlan show profile name="$p" key=clear 2>$null
            if ($d -match 'Authentication\s*:\s*Open') { $p }
        }).Count
    } 0
}

# =============================================================================
# 8. Backup and continuity  ->  A.5.30, A.5.33, A.8.13, A.8.14
# =============================================================================
Write-Step "Collecting backup and continuity state"

$wbSummary = Get-Safe {
    Import-Module WindowsServerBackup -ErrorAction Stop
    Get-WBSummary -ErrorAction Stop
}
$backupAgents = @('Veeam*','BackupExec*','AcronisAgent*','CommVault*','Rubrik*','CrashPlan*','Backupify*','DattoBackupAgent*','MARSAgent*')

$backup = [ordered]@{
    backup_configured   = Get-Safe {
        [bool]($wbSummary -or
               @(Get-Service -Name $backupAgents -ErrorAction SilentlyContinue).Count -gt 0 -or
               (Get-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\FileHistory' 'Enabled') -eq 1)
    } $false
    backup_product      = Get-Safe {
        $svc = Get-Service -Name $backupAgents -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($svc) { $svc.DisplayName } elseif ($wbSummary) { 'Windows Server Backup' } else { $null }
    }
    last_backup_days    = Get-Safe {
        if ($wbSummary -and $wbSummary.LastSuccessfulBackupTime) {
            [int]((Get-Date) - $wbSummary.LastSuccessfulBackupTime).TotalDays
        } else { $null }
    }
    last_backup_result  = Get-Safe { "$($wbSummary.LastBackupResultHR)" }
    backup_encrypted    = $null   # not discoverable locally - attest or supply from backup platform
    offsite_or_immutable= $null   # not discoverable locally - attest
    restore_tested_days = $null   # not discoverable locally - attest
    shadow_copies_enabled = Get-Safe {
        @(Get-CimInstance Win32_ShadowCopy -ErrorAction Stop).Count -gt 0
    } $false
    system_restore_enabled = Get-Safe {
        @(Get-ComputerRestorePoint -ErrorAction Stop).Count -gt 0
    } $false
}

# =============================================================================
# 9. Asset and software inventory  ->  A.5.9, A.5.12, A.5.32, A.8.19
# =============================================================================
Write-Step "Collecting asset and software inventory"

$uninstallKeys = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
$software = Get-Safe {
    @(Get-ItemProperty $uninstallKeys -ErrorAction SilentlyContinue |
      Where-Object { $_.DisplayName -and -not $_.SystemComponent } |
      Select-Object -ExpandProperty DisplayName -Unique | Sort-Object)
} @()

$approved = @()
if ($ApprovedSoftware -and (Test-Path $ApprovedSoftware)) {
    $approved = Get-Content $ApprovedSoftware | Where-Object { $_.Trim() }
    Write-Ok "Loaded $($approved.Count) approved application names"
}

# Applications commonly flagged in an ISO 27001 review: remote access, tunnelling,
# credential and network tooling that is rarely appropriate on a managed endpoint.
$riskyApps = @('TeamViewer','AnyDesk','LogMeIn','uTorrent','BitTorrent','Wireshark',
               'Nmap','Cain','KeePass Portable','Tor Browser','Hamachi','Ammyy',
               'RealVNC','UltraVNC','Advanced IP Scanner','ProcessHacker')

$unauthorized = Get-Safe {
    if ($approved.Count -gt 0) {
        @($software | Where-Object { $s = $_; -not ($approved | Where-Object { $s -like "*$_*" }) })
    } else {
        @($software | Where-Object { $s = $_; ($riskyApps | Where-Object { $s -like "*$_*" }) })
    }
} @()

$asset = [ordered]@{
    installed_software_count       = @($software).Count
    installed_software             = @($software | Select-Object -First 200)
    unauthorized_software          = @($unauthorized)
    unauthorized_software_count    = @($unauthorized).Count
    asset_tag                      = Get-Safe {
        $t = (Get-CimInstance Win32_SystemEnclosure -ErrorAction Stop).SMBIOSAssetTag
        if ($t -and "$t".Trim() -notin @('', 'No Asset Tag', 'Default string')) { "$t".Trim() }
        else { $bios.SerialNumber }
    }
    asset_owner                    = Get-Safe {
        $o = (Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).PrimaryOwnerName
        if ($o) { $o } else { $cs.UserName }
    }
    data_classification_labels_enabled = Get-Safe {
        [bool]((Test-Path 'HKLM:\SOFTWARE\Microsoft\MSIP') -or
               (Get-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Office\16.0\Common\Security' 'EnableLabelling') -eq 1 -or
               (Get-Service AIPService -ErrorAction SilentlyContinue))
    } $false
    dlp_enabled                    = Get-Safe {
        [bool]((Get-Service MdmDiagnostics, 'Microsoft.Purview*' -ErrorAction SilentlyContinue) -or
               (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Miscellaneous Configuration\DlpEnabled') -or
               (Get-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataLossPrevention' 'Enabled') -eq 1)
    } $false
    mdm_enrolled                   = Get-Safe {
        [bool](Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Enrollments' -ErrorAction Stop |
               Where-Object { (Get-ItemProperty $_.PSPath).EnrollmentState -eq 1 })
    } $false
}

# =============================================================================
# 10. Services, configuration drift, capacity, hardware
# =============================================================================
Write-Step "Collecting services, capacity and hardware health"

$running = Get-Safe { Get-Service | Where-Object Status -eq 'Running' } @()

$services = [ordered]@{
    running_service_count       = @($running).Count
    remote_registry_running     = Get-Safe { (Get-Service RemoteRegistry -ErrorAction Stop).Status -eq 'Running' } $false
    print_spooler_running       = Get-Safe { (Get-Service Spooler -ErrorAction Stop).Status -eq 'Running' } $false
    telnet_installed            = Get-Safe {
        $f = Get-WindowsOptionalFeature -Online -FeatureName TelnetClient -ErrorAction Stop
        ($f.State -eq 'Enabled')
    } $false
    unnecessary_services_running = Get-Safe {
        @(@('RemoteRegistry','SNMP','TlntSvr','FTPSVC','SSDPSRV','upnphost','WMPNetworkSvc','XblAuthManager') |
          Where-Object { (Get-Service $_ -ErrorAction SilentlyContinue).Status -eq 'Running' })
    } @()
}

# Configuration drift: count how many hardening expectations are currently unmet.
$driftChecks = @(
    @{ Name = 'SMBv1 enabled';              Bad = ($encryption.smbv1_enabled -eq $true) }
    @{ Name = 'SMB signing not required';   Bad = ($encryption.smb_signing_required -ne $true) }
    @{ Name = 'TLS 1.0 enabled';            Bad = ($encryption.tls10_enabled -eq $true) }
    @{ Name = 'TLS 1.1 enabled';            Bad = ($encryption.tls11_enabled -eq $true) }
    @{ Name = 'SSL 3.0 enabled';            Bad = ($encryption.ssl30_enabled -eq $true) }
    @{ Name = 'UAC disabled';               Bad = ($endpoint.uac_enabled -eq $false) }
    @{ Name = 'Secure Boot off';            Bad = ($endpoint.secure_boot_enabled -eq $false) }
    @{ Name = 'Guest account enabled';      Bad = ($identity.guest_account_enabled -eq $true) }
    @{ Name = 'Telnet installed';           Bad = ($services.telnet_installed -eq $true) }
    @{ Name = 'Remote Registry running';    Bad = ($services.remote_registry_running -eq $true) }
    @{ Name = 'LLMNR enabled';              Bad = ($network.llmnr_disabled -eq $false) }
    @{ Name = 'NetBIOS enabled';            Bad = ($network.netbios_enabled -eq $true) }
    @{ Name = 'Anonymous enumeration allowed'; Bad = ($network.anonymous_share_enumeration -eq $true) }
    @{ Name = 'No logon banner';            Bad = ($identity.logon_banner_configured -eq $false) }
)
$drift = @($driftChecks | Where-Object { $_.Bad } | ForEach-Object { $_.Name })

$configuration = [ordered]@{
    baseline_drift_count = $drift.Count
    baseline_drift_items = $drift
    baseline_reference   = 'CIS Microsoft Windows Benchmark (subset)'
}

$sysDrive = Get-Safe { Get-PSDrive -Name ($env:SystemDrive.TrimEnd(':')) -ErrorAction Stop }

$capacity = [ordered]@{
    system_drive_free_gb  = Get-Safe { [math]::Round($sysDrive.Free / 1GB, 1) }
    system_drive_total_gb = Get-Safe { [math]::Round(($sysDrive.Free + $sysDrive.Used) / 1GB, 1) }
    system_drive_free_pct = Get-Safe {
        [math]::Round(100 * $sysDrive.Free / ($sysDrive.Free + $sysDrive.Used), 1)
    }
    memory_total_gb       = Get-Safe { [math]::Round($cs.TotalPhysicalMemory / 1GB, 1) }
    memory_free_pct       = Get-Safe {
        [math]::Round(100 * $os.FreePhysicalMemory / $os.TotalVisibleMemorySize, 1)
    }
    cpu_load_pct          = Get-Safe { [int](Get-CimInstance Win32_Processor).LoadPercentage }
}

$hardware = [ordered]@{
    disk_health_ok   = Get-Safe {
        @(Get-PhysicalDisk -ErrorAction Stop | Where-Object { $_.HealthStatus -ne 'Healthy' }).Count -eq 0
    }
    disk_count       = Get-Safe { @(Get-PhysicalDisk -ErrorAction Stop).Count }
    battery_present  = Get-Safe { [bool](Get-CimInstance Win32_Battery -ErrorAction Stop) }
    chassis_type     = Get-Safe { "$((Get-CimInstance Win32_SystemEnclosure).ChassisTypes -join ',')" }
}

$data = [ordered]@{
    retention_policy_configured = Get-Safe {
        [bool]((Get-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Office\16.0\Common\Security' 'EnableLabelling') -eq 1 -or
               (Test-Path 'HKLM:\SOFTWARE\Microsoft\MSIP'))
    } $false
}

# =============================================================================
# 11. Assemble the report
# =============================================================================

$telemetry = [ordered]@{
    metadata            = $metadata
    identity            = $identity
    encryption          = $encryption
    logging             = $logging
    endpoint_protection = $endpoint
    patching            = $patching
    network             = $network
    backup              = $backup
    asset               = $asset
    services            = $services
    configuration       = $configuration
    capacity            = $capacity
    hardware            = $hardware
    data                = $data
}

if ($IncludeAttestations) {
    # Procedural Annex A controls the collector cannot measure. Set each to
    # true / false before uploading, or answer them in the web app.
    $telemetry['attestations'] = [ordered]@{
        isms_policy_approved              = $null
        security_roles_assigned           = $null
        segregation_of_duties_reviewed    = $null
        management_enforces_policy        = $null
        authority_contacts_maintained     = $null
        special_interest_groups           = $null
        threat_intel_process              = $null
        security_in_projects              = $null
        asset_inventory_maintained        = $null
        acceptable_use_policy_signed      = $null
        asset_return_process              = $null
        classification_scheme_defined     = $null
        labelling_procedure               = $null
        transfer_agreements               = $null
        access_control_policy             = $null
        joiner_mover_leaver_process       = $null
        access_review_performed           = $null
        supplier_risk_process             = $null
        supplier_security_clauses         = $null
        ict_supply_chain_managed          = $null
        supplier_service_reviews          = $null
        cloud_security_process            = $null
        incident_response_plan            = $null
        event_triage_process              = $null
        incident_response_executed        = $null
        post_incident_review              = $null
        forensic_procedure                = $null
        bc_security_maintained            = $null
        ict_continuity_tested             = $null
        legal_register_maintained         = $null
        ipr_compliance                    = $null
        records_retention_schedule        = $null
        privacy_requirements_met          = $null
        independent_review_done           = $null
        compliance_monitoring             = $null
        operating_procedures_documented   = $null
        background_screening              = $null
        employment_terms_security         = $null
        security_awareness_training       = $null
        disciplinary_process              = $null
        post_termination_duties           = $null
        nda_in_place                      = $null
        remote_working_policy             = $null
        event_reporting_channel           = $null
        physical_perimeter_defined        = $null
        physical_entry_controls           = $null
        facilities_secured                = $null
        physical_monitoring               = $null
        environmental_protection          = $null
        secure_area_rules                 = $null
        clear_desk_policy                 = $null
        equipment_siting                  = $null
        offsite_asset_protection          = $null
        media_handling_procedure          = $null
        utilities_protected               = $null
        cabling_secured                   = $null
        maintenance_schedule              = $null
        secure_disposal                   = $null
        source_code_access_controlled     = $null
        deletion_procedure                = $null
        data_masking_applied              = $null
        redundancy_designed               = $null
        network_segmentation              = $null
        secure_sdlc                       = $null
        app_security_requirements         = $null
        secure_architecture_principles    = $null
        secure_coding_standards           = $null
        security_testing_performed        = $null
        outsourced_dev_controlled         = $null
        environments_separated            = $null
        change_management_process         = $null
        test_data_protected               = $null
        audit_testing_controlled          = $null
    }
}

# =============================================================================
# 12. Write output
# =============================================================================

if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}
$OutputPath = (Resolve-Path $OutputPath).Path
$stamp      = Get-Date -Format 'yyyyMMdd-HHmmss'
$base       = Join-Path $OutputPath "ISOTelemetry_$($env:COMPUTERNAME)_$stamp"
$written    = @()

if ($Format -in @('Json', 'Both')) {
    $jsonPath = "$base.json"
    $telemetry | ConvertTo-Json -Depth 6 | Out-File -FilePath $jsonPath -Encoding utf8
    $written += $jsonPath
}

if ($Format -in @('Csv', 'Both')) {
    # Flatten to dotted key/value pairs; lists are joined with ';' so the web app
    # ingestion module can rebuild them.
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($section in $telemetry.Keys) {
        $block = $telemetry[$section]
        if ($block -isnot [System.Collections.IDictionary]) { continue }
        foreach ($key in $block.Keys) {
            $v = $block[$key]
            $out = if ($null -eq $v) { '' }
                   elseif ($v -is [bool]) { $v.ToString().ToLower() }
                   elseif ($v -is [array] -or $v -is [System.Collections.IList]) { ($v -join ';') }
                   else { "$v" }
            $rows.Add([pscustomobject]@{ key = "$section.$key"; value = $out })
        }
    }
    $csvPath = "$base.csv"
    $rows | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    $written += $csvPath
}

# =============================================================================
# 13. Console summary
# =============================================================================

if (-not $Quiet) {
    $paramCount = ($telemetry.Keys | ForEach-Object {
        if ($telemetry[$_] -is [System.Collections.IDictionary]) { $telemetry[$_].Keys.Count } else { 0 }
    } | Measure-Object -Sum).Sum

    Write-Host ""
    Write-Host "---------------------------------------------------------------" -ForegroundColor Cyan
    Write-Host "  Collection complete" -ForegroundColor Cyan
    Write-Host "---------------------------------------------------------------" -ForegroundColor Cyan
    Write-Host ("  Host                 : {0}" -f $metadata.hostname)
    Write-Host ("  Operating system     : {0}" -f $metadata.os_caption)
    Write-Host ("  Parameters collected : {0}" -f $paramCount)
    Write-Host ("  Baseline drift items : {0}" -f $configuration.baseline_drift_count)
    Write-Host ""

    # Quick pre-flight so the operator sees the obvious problems immediately.
    $flags = @()
    if ($encryption.disk_encryption_enabled -ne $true)   { $flags += 'Disk encryption not enabled (A.8.24, A.7.9)' }
    if ($endpoint.antivirus_enabled -ne $true)           { $flags += 'No anti-malware detected (A.8.7)' }
    if ($endpoint.firewall_public -eq $false)            { $flags += 'Firewall disabled on a profile (A.8.20)' }
    if ($identity.mfa_enabled -ne $true)                 { $flags += 'No MFA technology detected (A.8.5)' }
    # Guard the numeric comparisons: in PowerShell $null -lt 14 evaluates to $true,
    # which would report a false finding whenever a probe returned no data.
    if ($null -ne $identity.password_min_length -and
        $identity.password_min_length -lt 14)            { $flags += "Password minimum length is $($identity.password_min_length) (A.5.17)" }
    if ($null -ne $identity.lockout_threshold -and
        $identity.lockout_threshold -eq 0)               { $flags += 'Account lockout is disabled (A.5.17, A.8.5)' }
    if ($null -ne $patching.missing_critical_patches -and
        $patching.missing_critical_patches -gt 0)        { $flags += "$($patching.missing_critical_patches) critical patches missing (A.8.8)" }
    if ($network.risky_ports_open_count -gt 0)           { $flags += "High-risk ports listening: $($network.risky_ports_open -join ', ') (A.8.20)" }
    if ($encryption.smbv1_enabled -eq $true)             { $flags += 'SMBv1 is enabled (A.8.9)' }
    if ($backup.backup_configured -ne $true)             { $flags += 'No backup solution detected (A.8.13)' }

    if ($flags.Count -gt 0) {
        Write-Host "  Immediate flags:" -ForegroundColor Yellow
        $flags | ForEach-Object { Write-Host "    - $_" -ForegroundColor Yellow }
        Write-Host ""
    } else {
        Write-Ok "No headline issues detected in the pre-flight check"
        Write-Host ""
    }

    Write-Host "  Reports written:" -ForegroundColor Green
    $written | ForEach-Object { Write-Host "    $_" -ForegroundColor Green }
    Write-Host ""
    Write-Host "  Next step: upload the JSON (or CSV) file in the ISO 27001" -ForegroundColor Gray
    Write-Host "  Compliance Auditor web app to run the Annex A gap analysis." -ForegroundColor Gray
    Write-Host ""
}

# Return the paths so the script composes in a pipeline.
$written
