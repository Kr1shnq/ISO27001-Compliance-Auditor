"""
make_samples.py
---------------
Generates realistic sample telemetry files so the app can be demonstrated without
access to a live Windows host. Produces three profiles:

  hardened_server.json      well-managed Windows Server 2022 (high compliance)
  legacy_workstation.json   poorly managed Windows 10 endpoint (low compliance)
  mixed_endpoint.csv        partially hardened laptop, key/value CSV layout
"""

import csv
import json
import os
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))


def fake_serial(host: str) -> str:
    """Stable pseudo-serial for a host name.

    Uses crc32 rather than the builtin hash(): string hashing is salted per
    interpreter process, which made the generated samples differ on every run
    and left the working tree dirty after regeneration.
    """
    return f"SN-{zlib.crc32(host.encode()) % 10 ** 7:07d}"


def base(host, os_caption, server=False):
    return {
        "metadata": {
            "hostname": host,
            "fqdn": f"{host.lower()}.corp.acme.local",
            "os_caption": os_caption,
            "os_version": "10.0.20348" if server else "10.0.19045",
            "os_build": "21H2" if server else "22H2",
            "is_server": server,
            "domain": "corp.acme.local",
            "domain_joined": True,
            "manufacturer": "Dell Inc.",
            "model": "PowerEdge R650" if server else "Latitude 7430",
            "serial_number": fake_serial(host),
            "collected_utc": "2026-08-08T09:14:22Z",
            "collector_version": "1.0.0",
            "collected_elevated": True,
            "collected_by": "CORP\\svc-audit",
        }
    }


# ---------------------------------------------------------------------------
# 1. Hardened server — strong posture
# ---------------------------------------------------------------------------
hardened = base("SRV-APP-01", "Microsoft Windows Server 2022 Standard", server=True)
hardened.update({
    "identity": {
        "mfa_enabled": True, "mfa_providers": ["WindowsHelloForBusiness", "SmartCard"],
        "mfa_coverage_pct": 100, "local_user_count": 4, "local_admin_count": 2,
        "local_admin_members": ["CORP\\Domain Admins", "SRV-APP-01\\svc-admin"],
        "guest_account_enabled": False, "default_admin_renamed": True,
        "password_min_length": 15, "password_max_age_days": 90, "password_min_age_days": 1,
        "password_history_size": 24, "lockout_threshold": 5, "lockout_duration_min": 15,
        "lockout_window_min": 15, "password_complexity_enabled": True,
        "accounts_password_never_expires": 0, "inactive_accounts_90d": 0,
        "blank_password_accounts": 0, "laps_enabled": True,
        "credential_guard_enabled": True, "standard_users_cannot_install": True,
        "logon_banner_configured": True,
    },
    "encryption": {
        "disk_encryption_enabled": True, "disk_encryption_type": "XtsAes256",
        "encryption_percentage": 100, "key_protector_present": True,
        "key_protector_types": ["Tpm", "RecoveryPassword"], "recovery_key_escrowed": True,
        "unencrypted_volumes": [], "unencrypted_volume_count": 0,
        "removable_drive_encryption_required": True,
        "tls10_enabled": False, "tls11_enabled": False, "tls12_enabled": True,
        "tls13_enabled": True, "ssl30_enabled": False, "smb_signing_required": True,
        "smbv1_enabled": False, "fips_mode": True,
    },
    "logging": {
        "audit_logon_events": "Success and Failure", "audit_logoff_events": "Success",
        "audit_account_lockout": "Success and Failure", "audit_object_access": "Success and Failure",
        "audit_policy_change": "Success and Failure", "audit_privilege_use": "Success and Failure",
        "audit_account_management": "Success and Failure", "audit_process_creation": "Success",
        "logging_level": "Verbose", "security_log_max_size_mb": 4096,
        "security_log_retention_days": 365, "security_log_record_count": 8421337,
        "powershell_scriptblock_logging": True, "powershell_module_logging": True,
        "command_line_auditing": True, "log_forwarding_enabled": True,
        "siem_agents_detected": ["MDE.Windows", "splunkforwarder"],
        "time_sync_configured": True, "ntp_server": "dc01.corp.acme.local",
        "time_offset_seconds": 0.4,
    },
    "endpoint_protection": {
        "antivirus_enabled": True, "antivirus_product": "Microsoft Defender Antivirus",
        "realtime_protection": True, "behavior_monitoring": True, "signature_age_days": 0,
        "signature_version": "1.427.918.0", "last_full_scan_days": 3,
        "tamper_protection": True, "cloud_protection_enabled": True,
        "network_protection_enabled": True, "pua_protection_enabled": True,
        "asr_rules_enabled": 14, "edr_enabled": True, "firewall_domain": True,
        "firewall_private": True, "firewall_public": True, "inbound_default_block": True,
        "firewall_rule_count": 212, "secure_boot_enabled": True, "tpm_present": True,
        "tpm_ready": True, "tpm_version": "2.0", "uac_enabled": True,
        "applocker_or_wdac_enabled": True, "usb_storage_blocked": True,
        "screen_lock_timeout_min": 10, "screensaver_password_required": True,
    },
    "patching": {
        "auto_update_enabled": True, "last_patch_install_days": 6,
        "last_patch_kb": "KB5041160", "installed_patch_count": 74,
        "missing_critical_patches": 0, "pending_updates_total": 1,
        "pending_reboot": False, "os_supported": True,
        "wsus_server": "http://wsus.corp.acme.local:8530",
    },
    "network": {
        "rdp_enabled": True, "rdp_nla_required": True, "rdp_port": 3389,
        "open_listening_ports": [135, 445, 3389, 5985, 8443],
        "listening_port_count": 5, "risky_ports_open": [], "risky_ports_open_count": 0,
        "open_shares": ["AppData"], "open_shares_everyone": 0,
        "anonymous_share_enumeration": False, "netbios_enabled": False,
        "llmnr_disabled": True, "ipv6_enabled": True,
        "dns_servers": ["10.10.1.10", "10.10.1.11"], "dns_filtering_enabled": True,
        "vpn_configured": True, "host_firewall_isolation": True, "wifi_open_networks": 0,
    },
    "backup": {
        "backup_configured": True, "backup_product": "Veeam Backup & Replication",
        "last_backup_days": 1, "last_backup_result": "0", "backup_encrypted": True,
        "offsite_or_immutable": True, "restore_tested_days": 45,
        "shadow_copies_enabled": True, "system_restore_enabled": True,
    },
    "asset": {
        "installed_software_count": 38,
        "installed_software": ["Microsoft Defender", "Veeam Agent", "Splunk Universal Forwarder"],
        "unauthorized_software": [], "unauthorized_software_count": 0,
        "asset_tag": "ACME-SRV-0142",
        "asset_owner": "Infrastructure Operations",
        "data_classification_labels_enabled": True, "dlp_enabled": True, "mdm_enrolled": True,
    },
    "services": {
        "running_service_count": 96, "remote_registry_running": False,
        "print_spooler_running": False, "telnet_installed": False,
        "unnecessary_services_running": [],
    },
    "configuration": {
        "baseline_drift_count": 0, "baseline_drift_items": [],
        "baseline_reference": "CIS Microsoft Windows Server 2022 Benchmark v2.0",
    },
    "capacity": {
        "system_drive_free_gb": 220.4, "system_drive_total_gb": 512.0,
        "system_drive_free_pct": 43.0, "memory_total_gb": 128.0,
        "memory_free_pct": 61.2, "cpu_load_pct": 18,
    },
    "hardware": {"disk_health_ok": True, "disk_count": 4,
                 "battery_present": False, "chassis_type": "23"},
    "data": {"retention_policy_configured": True},
    "attestations": {
        "isms_policy_approved": True, "security_roles_assigned": True,
        "asset_inventory_maintained": True, "access_control_policy": True,
        "incident_response_plan": True, "security_awareness_training": True,
        "ict_continuity_tested": True, "change_management_process": True,
        "classification_scheme_defined": True, "joiner_mover_leaver_process": True,
    },
})

# ---------------------------------------------------------------------------
# 2. Legacy workstation — weak posture
# ---------------------------------------------------------------------------
legacy = base("WS-FIN-014", "Microsoft Windows 10 Pro")
legacy.update({
    "identity": {
        "mfa_enabled": False, "mfa_providers": [], "mfa_coverage_pct": 0,
        "local_user_count": 9, "local_admin_count": 7,
        "local_admin_members": ["WS-FIN-014\\Administrator", "WS-FIN-014\\jsmith",
                                "WS-FIN-014\\temp-it", "CORP\\Domain Admins"],
        "guest_account_enabled": True, "default_admin_renamed": False,
        "password_min_length": 6, "password_max_age_days": 0, "password_min_age_days": 0,
        "password_history_size": 0, "lockout_threshold": 0, "lockout_duration_min": 0,
        "lockout_window_min": 0, "password_complexity_enabled": False,
        "accounts_password_never_expires": 4, "inactive_accounts_90d": 3,
        "blank_password_accounts": 1, "laps_enabled": False,
        "credential_guard_enabled": False, "standard_users_cannot_install": False,
        "logon_banner_configured": False,
    },
    "encryption": {
        "disk_encryption_enabled": False, "disk_encryption_type": "None",
        "encryption_percentage": 0, "key_protector_present": False,
        "key_protector_types": [], "recovery_key_escrowed": False,
        "unencrypted_volumes": ["C:", "D:"], "unencrypted_volume_count": 2,
        "removable_drive_encryption_required": False,
        "tls10_enabled": True, "tls11_enabled": True, "tls12_enabled": True,
        "tls13_enabled": False, "ssl30_enabled": True, "smb_signing_required": False,
        "smbv1_enabled": True, "fips_mode": False,
    },
    "logging": {
        "audit_logon_events": "No Auditing", "audit_logoff_events": "No Auditing",
        "audit_account_lockout": "No Auditing", "audit_object_access": "No Auditing",
        "audit_policy_change": "No Auditing", "audit_privilege_use": "No Auditing",
        "audit_account_management": "Success", "audit_process_creation": "No Auditing",
        "logging_level": "Minimal", "security_log_max_size_mb": 20,
        "security_log_retention_days": 4, "security_log_record_count": 18422,
        "powershell_scriptblock_logging": False, "powershell_module_logging": False,
        "command_line_auditing": False, "log_forwarding_enabled": False,
        "siem_agents_detected": [], "time_sync_configured": False,
        "ntp_server": None, "time_offset_seconds": 47.8,
    },
    "endpoint_protection": {
        "antivirus_enabled": True, "antivirus_product": "Microsoft Defender Antivirus",
        "realtime_protection": False, "behavior_monitoring": False,
        "signature_age_days": 21, "signature_version": "1.401.220.0",
        "last_full_scan_days": 190, "tamper_protection": False,
        "cloud_protection_enabled": False, "network_protection_enabled": False,
        "pua_protection_enabled": False, "asr_rules_enabled": 0, "edr_enabled": False,
        "firewall_domain": True, "firewall_private": False, "firewall_public": False,
        "inbound_default_block": False, "firewall_rule_count": 88,
        "secure_boot_enabled": False, "tpm_present": False, "tpm_ready": False,
        "tpm_version": None, "uac_enabled": False, "applocker_or_wdac_enabled": False,
        "usb_storage_blocked": False, "screen_lock_timeout_min": 60,
        "screensaver_password_required": False,
    },
    "patching": {
        "auto_update_enabled": False, "last_patch_install_days": 287,
        "last_patch_kb": "KB5034763", "installed_patch_count": 31,
        "missing_critical_patches": 23, "pending_updates_total": 41,
        "pending_reboot": True, "os_supported": False, "wsus_server": None,
    },
    "network": {
        "rdp_enabled": True, "rdp_nla_required": False, "rdp_port": 3389,
        "open_listening_ports": [21, 23, 135, 139, 445, 3389, 5900],
        "listening_port_count": 7, "risky_ports_open": [21, 23, 135, 139, 445, 3389, 5900],
        "risky_ports_open_count": 7,
        "open_shares": ["Finance", "Public", "Temp"], "open_shares_everyone": 3,
        "anonymous_share_enumeration": True, "netbios_enabled": True,
        "llmnr_disabled": False, "ipv6_enabled": True,
        "dns_servers": ["10.10.1.10"], "dns_filtering_enabled": False,
        "vpn_configured": False, "host_firewall_isolation": False, "wifi_open_networks": 2,
    },
    "backup": {
        "backup_configured": False, "backup_product": None, "last_backup_days": None,
        "last_backup_result": None, "backup_encrypted": False,
        "offsite_or_immutable": False, "restore_tested_days": None,
        "shadow_copies_enabled": False, "system_restore_enabled": False,
    },
    "asset": {
        "installed_software_count": 147,
        "installed_software": ["TeamViewer 13", "uTorrent", "Adobe Reader XI"],
        "unauthorized_software": ["TeamViewer 13", "uTorrent", "AnyDesk", "Advanced IP Scanner"],
        "unauthorized_software_count": 4,
        "asset_tag": "", "asset_owner": None,
        "data_classification_labels_enabled": False, "dlp_enabled": False,
        "mdm_enrolled": False,
    },
    "services": {
        "running_service_count": 141, "remote_registry_running": True,
        "print_spooler_running": True, "telnet_installed": True,
        "unnecessary_services_running": ["RemoteRegistry", "SSDPSRV", "upnphost", "SNMP"],
    },
    "configuration": {
        "baseline_drift_count": 13,
        "baseline_drift_items": ["SMBv1 enabled", "SMB signing not required",
                                 "TLS 1.0 enabled", "TLS 1.1 enabled", "SSL 3.0 enabled",
                                 "UAC disabled", "Secure Boot off", "Guest account enabled",
                                 "Telnet installed", "Remote Registry running",
                                 "LLMNR enabled", "NetBIOS enabled",
                                 "Anonymous enumeration allowed"],
        "baseline_reference": "CIS Microsoft Windows 10 Benchmark v3.0",
    },
    "capacity": {
        "system_drive_free_gb": 9.2, "system_drive_total_gb": 256.0,
        "system_drive_free_pct": 3.6, "memory_total_gb": 8.0,
        "memory_free_pct": 7.1, "cpu_load_pct": 74,
    },
    "hardware": {"disk_health_ok": False, "disk_count": 1,
                 "battery_present": True, "chassis_type": "10"},
    "data": {"retention_policy_configured": False},
})

# ---------------------------------------------------------------------------
# 3. Mixed endpoint — moderate posture, exported as CSV key/value
# ---------------------------------------------------------------------------
mixed = base("LT-ENG-207", "Microsoft Windows 11 Enterprise")
mixed.update({
    "identity": {
        "mfa_enabled": True, "mfa_providers": ["WindowsHelloForBusiness"],
        "mfa_coverage_pct": 80, "local_user_count": 3, "local_admin_count": 4,
        "guest_account_enabled": False, "default_admin_renamed": False,
        "password_min_length": 12, "password_max_age_days": 365,
        "password_history_size": 10, "lockout_threshold": 15,
        "lockout_duration_min": 10, "password_complexity_enabled": True,
        "accounts_password_never_expires": 1, "inactive_accounts_90d": 1,
        "blank_password_accounts": 0, "laps_enabled": False,
        "credential_guard_enabled": True, "standard_users_cannot_install": False,
        "logon_banner_configured": True,
    },
    "encryption": {
        "disk_encryption_enabled": True, "disk_encryption_type": "XtsAes128",
        "encryption_percentage": 100, "key_protector_present": True,
        "key_protector_types": ["Tpm"], "recovery_key_escrowed": False,
        "unencrypted_volumes": ["D:"], "unencrypted_volume_count": 1,
        "removable_drive_encryption_required": False,
        "tls10_enabled": False, "tls11_enabled": True, "tls12_enabled": True,
        "tls13_enabled": True, "ssl30_enabled": False, "smb_signing_required": True,
        "smbv1_enabled": False, "fips_mode": False,
    },
    "logging": {
        "audit_logon_events": "Success and Failure", "audit_logoff_events": "Success",
        "audit_account_lockout": "Failure", "audit_object_access": "No Auditing",
        "audit_policy_change": "Success", "audit_privilege_use": "No Auditing",
        "audit_account_management": "Success", "audit_process_creation": "Success",
        "logging_level": "Standard", "security_log_max_size_mb": 128,
        "security_log_retention_days": 30, "security_log_record_count": 220145,
        "powershell_scriptblock_logging": True, "powershell_module_logging": False,
        "command_line_auditing": False, "log_forwarding_enabled": True,
        "siem_agents_detected": ["MDE.Windows"], "time_sync_configured": True,
        "ntp_server": "time.windows.com", "time_offset_seconds": 1.2,
    },
    "endpoint_protection": {
        "antivirus_enabled": True, "antivirus_product": "Microsoft Defender Antivirus",
        "realtime_protection": True, "behavior_monitoring": True, "signature_age_days": 1,
        "last_full_scan_days": 14, "tamper_protection": True,
        "cloud_protection_enabled": True, "network_protection_enabled": False,
        "pua_protection_enabled": True, "asr_rules_enabled": 3, "edr_enabled": True,
        "firewall_domain": True, "firewall_private": True, "firewall_public": True,
        "inbound_default_block": True, "firewall_rule_count": 176,
        "secure_boot_enabled": True, "tpm_present": True, "tpm_ready": True,
        "tpm_version": "2.0", "uac_enabled": True, "applocker_or_wdac_enabled": False,
        "usb_storage_blocked": False, "screen_lock_timeout_min": 15,
        "screensaver_password_required": True,
    },
    "patching": {
        "auto_update_enabled": True, "last_patch_install_days": 22,
        "last_patch_kb": "KB5040442", "installed_patch_count": 58,
        "missing_critical_patches": 3, "pending_updates_total": 7,
        "pending_reboot": True, "os_supported": True, "wsus_server": None,
    },
    "network": {
        "rdp_enabled": False, "rdp_nla_required": True, "rdp_port": 3389,
        "open_listening_ports": [135, 445, 5040],
        "listening_port_count": 3, "risky_ports_open": [135, 445], "risky_ports_open_count": 2,
        "open_shares": [], "open_shares_everyone": 0,
        "anonymous_share_enumeration": False, "netbios_enabled": True,
        "llmnr_disabled": True, "ipv6_enabled": True,
        "dns_servers": ["1.1.1.2"], "dns_filtering_enabled": True,
        "vpn_configured": True, "host_firewall_isolation": True, "wifi_open_networks": 1,
    },
    "backup": {
        "backup_configured": True, "backup_product": "OneDrive Known Folder Move",
        "last_backup_days": 2, "backup_encrypted": True,
        "offsite_or_immutable": False, "restore_tested_days": None,
        "shadow_copies_enabled": True, "system_restore_enabled": True,
    },
    "asset": {
        "installed_software_count": 82, "unauthorized_software": ["Wireshark"],
        "unauthorized_software_count": 1,
        "asset_tag": "ACME-LT-0207", "asset_owner": "Engineering",
        "data_classification_labels_enabled": True, "dlp_enabled": False,
        "mdm_enrolled": True,
    },
    "services": {
        "running_service_count": 118, "remote_registry_running": False,
        "print_spooler_running": True, "telnet_installed": False,
        "unnecessary_services_running": ["SSDPSRV"],
    },
    "configuration": {
        "baseline_drift_count": 3,
        "baseline_drift_items": ["TLS 1.1 enabled", "NetBIOS enabled",
                                 "Default Administrator not renamed"],
        "baseline_reference": "CIS Microsoft Windows 11 Benchmark v3.0",
    },
    "capacity": {
        "system_drive_free_gb": 96.3, "system_drive_total_gb": 512.0,
        "system_drive_free_pct": 18.8, "memory_total_gb": 32.0,
        "memory_free_pct": 34.5, "cpu_load_pct": 29,
    },
    "hardware": {"disk_health_ok": True, "disk_count": 1,
                 "battery_present": True, "chassis_type": "10"},
    "data": {"retention_policy_configured": True},
})


def write_json(name, payload):
    p = os.path.join(HERE, name)
    with open(p, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
    return p


def write_csv(name, payload):
    p = os.path.join(HERE, name)
    with open(p, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["key", "value"])
        for section, block in payload.items():
            if not isinstance(block, dict):
                continue
            for k, v in block.items():
                if isinstance(v, list):
                    v = ";".join(str(x) for x in v)
                elif isinstance(v, bool):
                    v = "true" if v else "false"
                elif v is None:
                    v = ""
                w.writerow([f"{section}.{k}", v])
    return p


if __name__ == "__main__":
    print(write_json("hardened_server.json", hardened))
    print(write_json("legacy_workstation.json", legacy))
    print(write_csv("mixed_endpoint.csv", mixed))
