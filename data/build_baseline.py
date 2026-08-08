"""
build_baseline.py
-----------------
Generates `iso27001_baseline.json` — the machine-readable ISO/IEC 27001:2022
Annex A control baseline used by the Compliance Auditor audit engine.

All 93 Annex A controls are represented across the four themes:
    A.5  Organizational  (37)
    A.6  People          (8)
    A.7  Physical        (14)
    A.8  Technological   (34)

Each control record:
{
  "id":            "A.8.5",
  "title":         "Secure authentication",
  "theme":         "Technological",
  "objective":     "short plain-English statement of intent",
  "mode":          "automated" | "manual" | "hybrid",
  "severity":      "High" | "Medium" | "Low",     # risk level applied when FAILED
  "attestation":   "key_in_telemetry.attestations",  # manual/hybrid only
  "checks": [ {"field": "...", "op": "...", "value": ..., "label": "..."} ],
  "remediation": [ "step 1", "step 2", ... ]
}

Operators supported by the audit engine (see app/audit_engine.py):
  eq, ne, gt, gte, lt, lte, in, not_in, truthy, falsy,
  len_eq, len_lte, len_gte, contains, not_contains, non_empty
"""

import json
import os

# --------------------------------------------------------------------------
# Helper constructors
# --------------------------------------------------------------------------

VALUELESS_OPS = {"truthy", "falsy", "non_empty"}


def chk(field, op, value=None, label=None):
    """Build a check spec.

    `truthy`, `falsy` and `non_empty` take no comparison value, so a third
    positional argument is interpreted as the human-readable label rather than
    being silently stored as an unused expected value.
    """
    if op in VALUELESS_OPS and value is not None and label is None:
        value, label = None, value
    d = {"field": field, "op": op, "label": label or field}
    if value is not None:
        d["value"] = value
    return d


def ctrl(cid, title, theme, objective, severity, mode="manual",
         checks=None, attestation=None, remediation=None):
    return {
        "id": cid,
        "title": title,
        "theme": theme,
        "objective": objective,
        "mode": mode,
        "severity": severity,
        "attestation": attestation,
        "checks": checks or [],
        "remediation": remediation or [],
    }


CONTROLS = []
A = CONTROLS.append

# ==========================================================================
# A.5 — ORGANIZATIONAL CONTROLS (37)
# ==========================================================================
ORG = "Organizational"

A(ctrl("A.5.1", "Policies for information security", ORG,
       "A documented, approved and communicated set of information security policies exists.",
       "High", "manual", attestation="isms_policy_approved",
       remediation=[
           "Draft an overarching Information Security Policy plus topic-specific policies (access control, cryptography, acceptable use, backup, incident response).",
           "Obtain formal sign-off from top management and record the approval date and version.",
           "Publish policies to a location all personnel can reach and record acknowledgement.",
           "Schedule a review at least annually or after any significant change."]))

A(ctrl("A.5.2", "Information security roles and responsibilities", ORG,
       "Security roles are defined and allocated to named individuals.",
       "High", "manual", attestation="security_roles_assigned",
       remediation=[
           "Produce a RACI matrix covering ISMS owner, risk owner, asset owners, incident manager and DPO.",
           "Reference the security responsibilities in job descriptions and employment contracts.",
           "Review allocations whenever staff join, move or leave."]))

A(ctrl("A.5.3", "Segregation of duties", ORG,
       "Conflicting duties and areas of responsibility are separated.",
       "Medium", "hybrid", attestation="segregation_of_duties_reviewed",
       checks=[chk("identity.local_admin_count", "lte", 3,
                   "No more than 3 local administrator accounts")],
       remediation=[
           "Map high-risk activities (approve, execute, review) and ensure no single account holds all three.",
           "Reduce standing local administrator membership; use just-in-time elevation.",
           "Where separation is impossible, add compensating monitoring and document the exception."]))

A(ctrl("A.5.4", "Management responsibilities", ORG,
       "Management requires all personnel to apply security per policy.",
       "Medium", "manual", attestation="management_enforces_policy",
       remediation=[
           "Add security objectives to management performance reviews.",
           "Have leadership formally communicate policy expectations at least annually.",
           "Track and report policy compliance to the management review meeting."]))

A(ctrl("A.5.5", "Contact with authorities", ORG,
       "Contacts with relevant authorities are maintained.",
       "Low", "manual", attestation="authority_contacts_maintained",
       remediation=[
           "List relevant authorities (national CERT, data protection regulator, law enforcement, sector regulator).",
           "Record named contacts, phone numbers and notification deadlines in the incident response plan.",
           "Verify the contact list every 6 months."]))

A(ctrl("A.5.6", "Contact with special interest groups", ORG,
       "Contact is maintained with security forums and professional associations.",
       "Low", "manual", attestation="special_interest_groups",
       remediation=[
           "Subscribe to vendor and sector advisory feeds (e.g. MSRC, CISA KEV, ISAC).",
           "Register at least one named person with a relevant professional body.",
           "Record how received advisories feed into the vulnerability management process."]))

A(ctrl("A.5.7", "Threat intelligence", ORG,
       "Threat information is collected and analysed to produce threat intelligence.",
       "Medium", "hybrid", attestation="threat_intel_process",
       checks=[chk("endpoint_protection.cloud_protection_enabled", "truthy",
                   label="Cloud-delivered threat intelligence enabled")],
       remediation=[
           "Enable cloud-delivered protection / reputation services on endpoint security tooling.",
           "Subscribe to strategic, tactical and operational threat feeds relevant to your sector.",
           "Define who reviews intelligence, how often, and how it triggers action."]))

A(ctrl("A.5.8", "Information security in project management", ORG,
       "Security is integrated into project management.",
       "Medium", "manual", attestation="security_in_projects",
       remediation=[
           "Add a mandatory security risk assessment gate to the project lifecycle.",
           "Require security acceptance criteria before go-live sign-off.",
           "Record security decisions in the project risk register."]))

A(ctrl("A.5.9", "Inventory of information and other associated assets", ORG,
       "An inventory of information and associated assets is maintained with owners.",
       "High", "hybrid", attestation="asset_inventory_maintained",
       checks=[chk("asset.asset_tag", "non_empty", label="Asset tag / identifier recorded"),
               chk("asset.asset_owner", "non_empty", label="Asset owner recorded"),
               chk("asset.installed_software_count", "gt", 0,
                   "Installed software inventory captured")],
       remediation=[
           "Populate an asset register covering hardware, software, data stores and cloud services.",
           "Assign a named owner to every asset and record its classification.",
           "Automate discovery so the register updates as devices and software change.",
           "Reconcile the register against discovery data at least quarterly."]))

A(ctrl("A.5.10", "Acceptable use of information and other associated assets", ORG,
       "Rules for acceptable use of assets are defined, documented and enforced.",
       "Medium", "hybrid", attestation="acceptable_use_policy_signed",
       checks=[chk("endpoint_protection.usb_storage_blocked", "truthy",
                   "Removable storage restricted"),
               chk("endpoint_protection.applocker_or_wdac_enabled", "truthy",
                   "Application control enforced")],
       remediation=[
           "Publish an Acceptable Use Policy and capture signed acknowledgement from every user.",
           "Enforce removable-media restrictions via Group Policy or Intune device control.",
           "Deploy AppLocker or WDAC in enforce mode to restrict unapproved applications."]))

A(ctrl("A.5.11", "Return of assets", ORG,
       "Personnel return organisational assets on termination of employment or contract.",
       "Medium", "manual", attestation="asset_return_process",
       remediation=[
           "Add an asset-return checklist to the offboarding workflow.",
           "Reconcile returned items against the asset register and record the outcome.",
           "Remotely wipe or disable any asset not returned within the agreed window."]))

A(ctrl("A.5.12", "Classification of information", ORG,
       "Information is classified according to confidentiality, integrity and availability needs.",
       "High", "hybrid", attestation="classification_scheme_defined",
       checks=[chk("asset.data_classification_labels_enabled", "truthy",
                   "Classification labelling technology enabled")],
       remediation=[
           "Define a classification scheme (e.g. Public / Internal / Confidential / Restricted) with handling rules.",
           "Deploy sensitivity labels (Microsoft Purview Information Protection or equivalent).",
           "Train users on selecting the right label and audit label usage."]))

A(ctrl("A.5.13", "Labelling of information", ORG,
       "Procedures for labelling information are implemented in line with the classification scheme.",
       "Medium", "hybrid", attestation="labelling_procedure",
       checks=[chk("asset.data_classification_labels_enabled", "truthy",
                   "Automatic / mandatory labelling active")],
       remediation=[
           "Configure mandatory labelling so documents and email cannot be saved or sent unlabelled.",
           "Apply visual markings (headers, footers, watermarks) driven by the label.",
           "Extend labelling to physical media and printed output."]))

A(ctrl("A.5.14", "Information transfer", ORG,
       "Transfer rules and controls protect information in transit within and outside the organisation.",
       "High", "hybrid", attestation="transfer_agreements",
       checks=[chk("encryption.tls12_enabled", "truthy", "TLS 1.2 or higher available"),
               chk("encryption.smb_signing_required", "truthy", "SMB signing required"),
               chk("encryption.smbv1_enabled", "falsy", "Legacy SMBv1 disabled")],
       remediation=[
           "Force TLS 1.2/1.3 for all transfers and disable SSL 3.0, TLS 1.0 and TLS 1.1.",
           "Set 'Digitally sign communications (always)' for SMB client and server.",
           "Remove the SMB 1.0/CIFS Windows feature entirely.",
           "Document approved transfer channels and require encryption for external transfers."]))

A(ctrl("A.5.15", "Access control", ORG,
       "Access to information and assets is granted per an access control policy.",
       "High", "hybrid", attestation="access_control_policy",
       checks=[chk("identity.guest_account_enabled", "falsy", "Guest account disabled"),
               chk("identity.local_admin_count", "lte", 3, "Local admin group is minimal"),
               chk("network.open_shares_everyone", "lte", 0,
                   "No shares granted to 'Everyone'")],
       remediation=[
           "Disable the built-in Guest account and any generic shared logins.",
           "Remove standing local administrator rights; grant on a role basis only.",
           "Replace 'Everyone' share permissions with specific security groups.",
           "Document and enforce a formal access control policy based on least privilege."]))

A(ctrl("A.5.16", "Identity management", ORG,
       "The full lifecycle of identities is managed.",
       "High", "hybrid", attestation="joiner_mover_leaver_process",
       checks=[chk("identity.inactive_accounts_90d", "lte", 0,
                   "No accounts dormant for 90+ days"),
               chk("identity.default_admin_renamed", "truthy",
                   "Default Administrator account renamed")],
       remediation=[
           "Disable accounts with no logon in 90 days and delete after a defined retention period.",
           "Rename the built-in Administrator account and create a decoy with no privileges.",
           "Automate provisioning/deprovisioning from the HR system of record.",
           "Recertify all identities at least every 6 months."]))

A(ctrl("A.5.17", "Authentication information", ORG,
       "Allocation and management of authentication information is controlled.",
       "High", "automated",
       checks=[chk("identity.password_min_length", "gte", 14, "Minimum password length >= 14"),
               chk("identity.password_complexity_enabled", "truthy", "Complexity enforced"),
               chk("identity.password_history_size", "gte", 24, "Password history >= 24"),
               chk("identity.lockout_threshold", "gte", 1, "Account lockout is enabled"),
               chk("identity.lockout_threshold", "lte", 10, "Lockout threshold is <= 10 attempts"),
               chk("identity.lockout_duration_min", "gte", 15,
                   "Lockout duration >= 15 minutes"),
               chk("identity.blank_password_accounts", "lte", 0,
                   "No accounts permit a blank password"),
               chk("identity.laps_enabled", "truthy", "Local admin password solution (LAPS) in use")],
       remediation=[
           "Set minimum password length to 14+ characters via Group Policy or Intune.",
           "Enable complexity requirements and a password history of 24.",
           "Configure account lockout: threshold 5-10, duration 15 minutes, reset counter 15 minutes.",
           "Deploy Windows LAPS so every device has a unique, rotated local admin password.",
           "Move toward passwordless / phishing-resistant authentication where supported."]))

A(ctrl("A.5.18", "Access rights", ORG,
       "Access rights are provisioned, reviewed, modified and removed per policy.",
       "High", "hybrid", attestation="access_review_performed",
       checks=[chk("identity.accounts_password_never_expires", "lte", 0,
                   "No accounts flagged 'password never expires'"),
               chk("identity.inactive_accounts_90d", "lte", 0,
                   "No stale accounts retaining access")],
       remediation=[
           "Clear the 'password never expires' flag except for documented, vaulted service accounts.",
           "Run a formal access recertification campaign with owner sign-off every 6 months.",
           "Revoke all access within 24 hours of termination and evidence the revocation."]))

A(ctrl("A.5.19", "Information security in supplier relationships", ORG,
       "Risks from supplier use of organisational assets are managed.",
       "Medium", "manual", attestation="supplier_risk_process",
       remediation=[
           "Maintain a supplier register with a criticality rating for each.",
           "Perform security due diligence before onboarding and re-assess annually for critical suppliers.",
           "Define what suppliers may access and under what conditions."]))

A(ctrl("A.5.20", "Addressing information security within supplier agreements", ORG,
       "Security requirements are agreed with each supplier in writing.",
       "Medium", "manual", attestation="supplier_security_clauses",
       remediation=[
           "Add security schedules to contracts: incident notification SLA, right to audit, sub-processor rules, data return/destruction.",
           "Require evidence of certification (ISO 27001, SOC 2) where proportionate.",
           "Track contract renewal dates so clauses stay current."]))

A(ctrl("A.5.21", "Managing information security in the ICT supply chain", ORG,
       "Risks associated with the ICT products and services supply chain are managed.",
       "Medium", "manual", attestation="ict_supply_chain_managed",
       remediation=[
           "Require a software bill of materials (SBOM) from critical software vendors.",
           "Verify component authenticity and code signing before deployment.",
           "Assess the security posture of upstream sub-suppliers for critical services."]))

A(ctrl("A.5.22", "Monitoring, review and change management of supplier services", ORG,
       "Supplier service delivery is monitored, reviewed and changes are managed.",
       "Medium", "manual", attestation="supplier_service_reviews",
       remediation=[
           "Hold scheduled service reviews with critical suppliers and minute the security items.",
           "Review supplier assurance reports (SOC 2 Type II, pen test summaries) on receipt.",
           "Assess the security impact of any supplier-initiated change before accepting it."]))

A(ctrl("A.5.23", "Information security for use of cloud services", ORG,
       "Processes for acquisition, use, management and exit of cloud services are defined.",
       "High", "manual", attestation="cloud_security_process",
       remediation=[
           "Maintain a register of sanctioned cloud services and block unsanctioned ones.",
           "Document the shared responsibility split for each service.",
           "Apply CIS/vendor benchmarks to cloud tenant configuration and monitor drift.",
           "Define and test an exit plan including data export and deletion."]))

A(ctrl("A.5.24", "Information security incident management planning and preparation", ORG,
       "The organisation plans and prepares for incident management.",
       "High", "manual", attestation="incident_response_plan",
       remediation=[
           "Publish an incident response plan defining severity levels, roles and escalation paths.",
           "Maintain 24/7 contact details for the response team and key third parties.",
           "Run a tabletop exercise at least annually and record lessons learned."]))

A(ctrl("A.5.25", "Assessment and decision on information security events", ORG,
       "Events are assessed and classified as incidents or not.",
       "Medium", "hybrid", attestation="event_triage_process",
       checks=[chk("logging.log_forwarding_enabled", "truthy",
                   "Events forwarded to a central platform / SIEM")],
       remediation=[
           "Forward Windows event logs to a SIEM or central collector.",
           "Define triage criteria that turn an event into a classified incident.",
           "Record the assessment decision and rationale for every escalated event."]))

A(ctrl("A.5.26", "Response to information security incidents", ORG,
       "Incidents are responded to in accordance with documented procedures.",
       "High", "manual", attestation="incident_response_executed",
       remediation=[
           "Write per-scenario runbooks (ransomware, account compromise, data loss).",
           "Log every response action with timestamps in a ticketing system.",
           "Confirm containment, eradication and recovery steps before closing an incident."]))

A(ctrl("A.5.27", "Learning from information security incidents", ORG,
       "Knowledge from incidents is used to strengthen controls.",
       "Medium", "manual", attestation="post_incident_review",
       remediation=[
           "Hold a blameless post-incident review for every high-severity incident.",
           "Convert root causes into tracked corrective actions with owners and dates.",
           "Feed incident trends into the annual risk assessment."]))

A(ctrl("A.5.28", "Collection of evidence", ORG,
       "Procedures exist for the identification, collection and preservation of evidence.",
       "Medium", "hybrid", attestation="forensic_procedure",
       checks=[chk("logging.security_log_retention_days", "gte", 90,
                   "Security log retained at least 90 days"),
               chk("logging.security_log_max_size_mb", "gte", 1024,
                   "Security log sized at least 1 GB")],
       remediation=[
           "Increase the Security event log to 1 GB or more and set retention to 90+ days.",
           "Archive logs to immutable/WORM storage so they cannot be altered.",
           "Document a chain-of-custody procedure and identify a forensics provider in advance."]))

A(ctrl("A.5.29", "Information security during disruption", ORG,
       "Security is maintained during disruption.",
       "Medium", "manual", attestation="bc_security_maintained",
       remediation=[
           "Document how each security control operates in degraded / failover mode.",
           "Ensure DR environments enforce the same access control and logging as production.",
           "Include security validation in every business continuity test."]))

A(ctrl("A.5.30", "ICT readiness for business continuity", ORG,
       "ICT readiness is planned, implemented, maintained and tested against continuity objectives.",
       "High", "hybrid", attestation="ict_continuity_tested",
       checks=[chk("backup.backup_configured", "truthy", "Backup solution configured"),
               chk("backup.restore_tested_days", "lte", 180,
                   "Restore tested within the last 180 days")],
       remediation=[
           "Define RTO and RPO per service and design backup frequency to meet them.",
           "Configure and verify a working backup job on every in-scope system.",
           "Perform and document a full restore test at least every 6 months."]))

A(ctrl("A.5.31", "Legal, statutory, regulatory and contractual requirements", ORG,
       "Applicable legal and contractual requirements are identified and met.",
       "Medium", "manual", attestation="legal_register_maintained",
       remediation=[
           "Maintain a legal and regulatory register mapped to controls that satisfy each obligation.",
           "Assign an owner to monitor changes in law affecting the ISMS scope.",
           "Review the register at least annually with legal counsel."]))

A(ctrl("A.5.32", "Intellectual property rights", ORG,
       "Procedures protect intellectual property rights, including software licensing.",
       "Low", "hybrid", attestation="ipr_compliance",
       checks=[chk("asset.unauthorized_software_count", "lte", 0,
                   "No unlicensed / unauthorised software detected")],
       remediation=[
           "Reconcile installed software against purchased licence entitlements.",
           "Remove or license any software flagged as unauthorised.",
           "Block installation of unapproved software with application control."]))

A(ctrl("A.5.33", "Protection of records", ORG,
       "Records are protected from loss, destruction, falsification and unauthorised access.",
       "Medium", "hybrid", attestation="records_retention_schedule",
       checks=[chk("logging.security_log_retention_days", "gte", 90,
                   "Log records retained per schedule"),
               chk("backup.backup_encrypted", "truthy", "Backup copies of records encrypted")],
       remediation=[
           "Publish a retention schedule stating how long each record type is kept and why.",
           "Encrypt backups and apply immutability / legal-hold where records are regulated.",
           "Restrict deletion rights on record repositories and log all deletions."]))

A(ctrl("A.5.34", "Privacy and protection of PII", ORG,
       "Privacy and PII protection requirements are identified and met.",
       "High", "hybrid", attestation="privacy_requirements_met",
       checks=[chk("asset.dlp_enabled", "truthy", "Data loss prevention active"),
               chk("encryption.disk_encryption_enabled", "truthy",
                   "PII at rest protected by disk encryption")],
       remediation=[
           "Map where PII is stored, processed and transmitted, and record the lawful basis.",
           "Enable DLP policies that detect and block unauthorised PII egress.",
           "Ensure full-disk encryption on every device that may hold PII.",
           "Define and test the data subject request and breach notification workflow."]))

A(ctrl("A.5.35", "Independent review of information security", ORG,
       "The security approach is independently reviewed at planned intervals.",
       "Medium", "manual", attestation="independent_review_done",
       remediation=[
           "Schedule an internal ISMS audit programme covering all clauses and Annex A controls annually.",
           "Use auditors independent of the area being audited.",
           "Track findings to closure and report results to management review."]))

A(ctrl("A.5.36", "Compliance with policies, rules and standards for information security", ORG,
       "Compliance with the security policy and standards is regularly reviewed.",
       "Medium", "hybrid", attestation="compliance_monitoring",
       checks=[chk("patching.os_supported", "truthy", "Operating system is vendor-supported"),
               chk("configuration.baseline_drift_count", "lte", 5,
                   "Configuration drift from baseline is minimal")],
       remediation=[
           "Run automated configuration compliance scans (this tool, SCM, Intune compliance policies).",
           "Upgrade or isolate any system running an unsupported operating system.",
           "Report compliance metrics to management on a fixed cadence."]))

A(ctrl("A.5.37", "Documented operating procedures", ORG,
       "Operating procedures for information processing facilities are documented and available.",
       "Low", "manual", attestation="operating_procedures_documented",
       remediation=[
           "Document runbooks for backup, patching, account administration and incident handling.",
           "Store procedures where operators can reach them during an outage (including offline).",
           "Review each procedure annually and after any material change."]))

# ==========================================================================
# A.6 — PEOPLE CONTROLS (8)
# ==========================================================================
PPL = "People"

A(ctrl("A.6.1", "Screening", PPL,
       "Background verification is carried out on candidates before employment.",
       "Medium", "manual", attestation="background_screening",
       remediation=[
           "Define screening levels proportionate to role risk and applicable law.",
           "Verify identity, right to work, references and qualifications before start date.",
           "Re-screen personnel moving into high-privilege roles."]))

A(ctrl("A.6.2", "Terms and conditions of employment", PPL,
       "Employment agreements state security responsibilities.",
       "Medium", "manual", attestation="employment_terms_security",
       remediation=[
           "Insert information security obligations into employment and contractor agreements.",
           "State that obligations survive termination where applicable.",
           "Retain signed copies as evidence."]))

A(ctrl("A.6.3", "Information security awareness, education and training", PPL,
       "Personnel receive appropriate security awareness training and updates.",
       "High", "manual", attestation="security_awareness_training",
       remediation=[
           "Deliver induction training before granting system access.",
           "Run refresher training at least annually plus periodic phishing simulations.",
           "Track completion rates and follow up non-completers.",
           "Provide role-specific training for developers and privileged administrators."]))

A(ctrl("A.6.4", "Disciplinary process", PPL,
       "A formal disciplinary process for security policy violations exists and is communicated.",
       "Low", "manual", attestation="disciplinary_process",
       remediation=[
           "Document a graduated disciplinary process for security violations.",
           "Communicate it as part of policy acknowledgement.",
           "Apply it consistently and record outcomes."]))

A(ctrl("A.6.5", "Responsibilities after termination or change of employment", PPL,
       "Post-employment security responsibilities are defined and enforced.",
       "Medium", "manual", attestation="post_termination_duties",
       remediation=[
           "Define which obligations (confidentiality, IP) continue after employment ends.",
           "Remind leavers of these duties in the exit interview and record acknowledgement.",
           "Confirm all access is revoked as part of the offboarding checklist."]))

A(ctrl("A.6.6", "Confidentiality or non-disclosure agreements", PPL,
       "NDAs reflecting protection needs are identified, documented and signed.",
       "Medium", "manual", attestation="nda_in_place",
       remediation=[
           "Require signed NDAs from employees, contractors and third parties before access.",
           "Review NDA wording against current classification and legal requirements annually.",
           "Store executed agreements in a retrievable repository."]))

A(ctrl("A.6.7", "Remote working", PPL,
       "Security measures protect information accessed or stored outside organisational premises.",
       "High", "hybrid", attestation="remote_working_policy",
       checks=[chk("encryption.disk_encryption_enabled", "truthy",
                   "Full-disk encryption enabled on the device"),
               chk("network.vpn_configured", "truthy", "Managed VPN client present"),
               chk("endpoint_protection.screen_lock_timeout_min", "lte", 15,
                   "Screen lock after 15 minutes or less")],
       remediation=[
           "Enable BitLocker (or equivalent) on every mobile and remote-working device.",
           "Require an always-on or managed VPN for access to internal resources.",
           "Enforce a 10-15 minute screen lock with password resume.",
           "Publish a remote working policy covering home networks, public Wi-Fi and physical security."]))

A(ctrl("A.6.8", "Information security event reporting", PPL,
       "Personnel can report observed or suspected security events through appropriate channels.",
       "Medium", "manual", attestation="event_reporting_channel",
       remediation=[
           "Publish a single, well-known reporting channel (email alias, portal button, hotline).",
           "Guarantee no-blame reporting to encourage early disclosure.",
           "Acknowledge every report and confirm the outcome to the reporter."]))

# ==========================================================================
# A.7 — PHYSICAL CONTROLS (14)
# ==========================================================================
PHY = "Physical"

A(ctrl("A.7.1", "Physical security perimeters", PHY,
       "Security perimeters are defined and used to protect areas containing information assets.",
       "Medium", "manual", attestation="physical_perimeter_defined",
       remediation=[
           "Document site perimeters and identify which assets sit inside each.",
           "Ensure walls, doors and windows to secure areas resist forced entry.",
           "Inspect perimeter integrity on a scheduled basis."]))

A(ctrl("A.7.2", "Physical entry", PHY,
       "Secure areas are protected by appropriate entry controls.",
       "Medium", "manual", attestation="physical_entry_controls",
       remediation=[
           "Deploy badge or biometric access to secure areas and log every entry.",
           "Escort and sign in all visitors; issue visibly distinct visitor badges.",
           "Review access lists to secure areas quarterly."]))

A(ctrl("A.7.3", "Securing offices, rooms and facilities", PHY,
       "Physical security for offices, rooms and facilities is designed and applied.",
       "Low", "manual", attestation="facilities_secured",
       remediation=[
           "Avoid signage that identifies sensitive processing areas.",
           "Lock server, comms and records rooms independently of the general office.",
           "Keep directories listing sensitive facility locations out of public reach."]))

A(ctrl("A.7.4", "Physical security monitoring", PHY,
       "Premises are continuously monitored for unauthorised physical access.",
       "Medium", "manual", attestation="physical_monitoring",
       remediation=[
           "Install CCTV and intruder alarms covering entrances to secure areas.",
           "Set a retention period for footage that meets investigation and legal needs.",
           "Test alarm response procedures periodically."]))

A(ctrl("A.7.5", "Protecting against physical and environmental threats", PHY,
       "Protection against physical and environmental threats is designed and implemented.",
       "Medium", "manual", attestation="environmental_protection",
       remediation=[
           "Assess flood, fire, seismic and civil-unrest risk for each site.",
           "Install fire detection/suppression and environmental monitoring in technical rooms.",
           "Site critical equipment away from water pipes and external walls."]))

A(ctrl("A.7.6", "Working in secure areas", PHY,
       "Security measures for working in secure areas are designed and implemented.",
       "Low", "manual", attestation="secure_area_rules",
       remediation=[
           "Publish rules for secure areas (no unescorted work, no recording devices).",
           "Restrict knowledge of secure area activity on a need-to-know basis.",
           "Keep secure areas locked and periodically inspected when vacant."]))

A(ctrl("A.7.7", "Clear desk and clear screen", PHY,
       "Clear desk and clear screen rules are defined and enforced.",
       "Medium", "hybrid", attestation="clear_desk_policy",
       checks=[chk("endpoint_protection.screen_lock_timeout_min", "lte", 15,
                   "Automatic screen lock <= 15 minutes"),
               chk("endpoint_protection.screensaver_password_required", "truthy",
                   "Password required to resume from lock")],
       remediation=[
           "Set the inactivity lock to 10-15 minutes and require a password on resume via GPO/Intune.",
           "Publish and spot-check a clear desk policy covering paper and removable media.",
           "Provide lockable storage and secure shredding at every desk area."]))

A(ctrl("A.7.8", "Equipment siting and protection", PHY,
       "Equipment is sited securely and protected.",
       "Low", "manual", attestation="equipment_siting",
       remediation=[
           "Position screens so sensitive information is not visible to passers-by.",
           "Secure equipment in racks or with locks in shared and public areas.",
           "Control eating, drinking and smoking near critical equipment."]))

A(ctrl("A.7.9", "Security of assets off-premises", PHY,
       "Assets used away from organisational premises are protected.",
       "High", "hybrid", attestation="offsite_asset_protection",
       checks=[chk("encryption.disk_encryption_enabled", "truthy",
                   "Device encrypted for off-premises use"),
               chk("endpoint_protection.tpm_present", "truthy",
                   "TPM present to protect encryption keys")],
       remediation=[
           "Enable BitLocker with TPM (plus PIN for high-risk roles) on all portable devices.",
           "Register off-site assets and record the responsible custodian.",
           "Enable remote lock and wipe through the MDM platform.",
           "Instruct users never to leave devices unattended in vehicles or public spaces."]))

A(ctrl("A.7.10", "Storage media", PHY,
       "Storage media is managed through acquisition, use, transportation and disposal.",
       "Medium", "hybrid", attestation="media_handling_procedure",
       checks=[chk("endpoint_protection.usb_storage_blocked", "truthy",
                   "Unmanaged removable media blocked"),
               chk("encryption.removable_drive_encryption_required", "truthy",
                   "Encryption required for writable removable media")],
       remediation=[
           "Block unmanaged USB mass storage; allow only encrypted, registered media.",
           "Enable BitLocker To Go and deny write access to unencrypted removable drives.",
           "Log the movement of media containing classified information."]))

A(ctrl("A.7.11", "Supporting utilities", PHY,
       "Facilities are protected from power failures and other utility disruptions.",
       "Medium", "manual", attestation="utilities_protected",
       remediation=[
           "Provide UPS coverage for critical equipment and test batteries on schedule.",
           "Arrange generator or alternate power for sites with long recovery objectives.",
           "Monitor utility alarms and include utility failure in continuity testing."]))

A(ctrl("A.7.12", "Cabling security", PHY,
       "Power and telecommunications cabling is protected from interception and damage.",
       "Low", "manual", attestation="cabling_secured",
       remediation=[
           "Route network cabling through conduit and avoid public or unsecured areas.",
           "Separate power and data cabling to limit interference.",
           "Label and document patching; lock comms cabinets."]))

A(ctrl("A.7.13", "Equipment maintenance", PHY,
       "Equipment is maintained correctly to ensure availability and integrity.",
       "Low", "hybrid", attestation="maintenance_schedule",
       checks=[chk("hardware.disk_health_ok", "truthy", "Disk health reported healthy")],
       remediation=[
           "Follow vendor maintenance intervals and use authorised service providers.",
           "Monitor SMART / predictive failure alerts and replace failing disks promptly.",
           "Remove or sanitise data before equipment leaves the site for repair."]))

A(ctrl("A.7.14", "Secure disposal or re-use of equipment", PHY,
       "Equipment is verified to be free of sensitive data before disposal or re-use.",
       "Medium", "manual", attestation="secure_disposal",
       remediation=[
           "Cryptographically erase or physically destroy media before disposal.",
           "Obtain certificates of destruction from disposal vendors and retain them.",
           "Update the asset register when an asset is disposed of or reassigned."]))

# ==========================================================================
# A.8 — TECHNOLOGICAL CONTROLS (34)
# ==========================================================================
TEC = "Technological"

A(ctrl("A.8.1", "User end point devices", TEC,
       "Information on user endpoint devices is protected.",
       "High", "automated",
       checks=[chk("encryption.disk_encryption_enabled", "truthy", "Full-disk encryption on"),
               chk("endpoint_protection.antivirus_enabled", "truthy", "Anti-malware enabled"),
               chk("endpoint_protection.uac_enabled", "truthy", "User Account Control enabled"),
               chk("endpoint_protection.screen_lock_timeout_min", "lte", 15,
                   "Screen lock <= 15 minutes")],
       remediation=[
           "Enable BitLocker on the OS volume and all fixed data volumes.",
           "Ensure Microsoft Defender (or approved AV) is enabled with real-time protection.",
           "Set UAC to 'Always notify' for administrators.",
           "Enforce a 15-minute inactivity lock with password on resume."]))

A(ctrl("A.8.2", "Privileged access rights", TEC,
       "Allocation and use of privileged access rights is restricted and managed.",
       "High", "automated",
       checks=[chk("identity.local_admin_count", "lte", 3, "Local administrators <= 3"),
               chk("identity.laps_enabled", "truthy", "LAPS deployed for local admin passwords"),
               chk("identity.credential_guard_enabled", "truthy",
                   "Credential Guard protecting privileged credentials"),
               chk("identity.default_admin_renamed", "truthy",
                   "Built-in Administrator renamed")],
       remediation=[
           "Remove standing local admin rights; use separate admin accounts or JIT elevation (PIM).",
           "Deploy Windows LAPS to randomise and rotate local administrator passwords.",
           "Enable Credential Guard (VBS) to block credential theft.",
           "Rename the built-in Administrator account and audit its use.",
           "Log and review all privileged session activity."]))

A(ctrl("A.8.3", "Information access restriction", TEC,
       "Access to information and application functions is restricted per the access control policy.",
       "High", "automated",
       checks=[chk("network.open_shares_everyone", "lte", 0,
                   "No file shares open to 'Everyone'"),
               chk("identity.guest_account_enabled", "falsy", "Guest account disabled"),
               chk("network.anonymous_share_enumeration", "falsy",
                   "Anonymous share enumeration blocked")],
       remediation=[
           "Replace 'Everyone' ACLs with least-privilege security groups on all shares.",
           "Disable the Guest account and anonymous access.",
           "Set 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' to Enabled.",
           "Review folder permissions against data classification annually."]))

A(ctrl("A.8.4", "Access to source code", TEC,
       "Read and write access to source code and development tools is appropriately managed.",
       "Medium", "manual", attestation="source_code_access_controlled",
       remediation=[
           "Store source code in a managed repository with SSO and MFA enforced.",
           "Require branch protection and peer review before merge to protected branches.",
           "Audit repository permissions quarterly and remove unused collaborators.",
           "Scan repositories for committed secrets."]))

A(ctrl("A.8.5", "Secure authentication", TEC,
       "Secure authentication technologies and procedures are implemented.",
       "High", "automated",
       checks=[chk("identity.mfa_enabled", "truthy", "Multi-factor authentication enabled"),
               chk("identity.mfa_coverage_pct", "gte", 95, "MFA covers >= 95% of accounts"),
               chk("identity.lockout_threshold", "gte", 1, "Account lockout is enabled"),
               chk("identity.lockout_threshold", "lte", 10, "Lockout threshold is <= 10 attempts"),
               chk("network.rdp_nla_required", "truthy",
                   "Network Level Authentication required for RDP")],
       remediation=[
           "Enforce MFA for all interactive and remote access; prefer phishing-resistant factors (FIDO2, Windows Hello for Business).",
           "Extend MFA coverage to 100% of accounts, including break-glass (with compensating controls).",
           "Configure account lockout after 5-10 failed attempts.",
           "Require Network Level Authentication on every RDP-enabled host.",
           "Display a logon banner and suppress the last-logged-on username."]))

A(ctrl("A.8.6", "Capacity management", TEC,
       "Resource use is monitored and adjusted to meet capacity requirements.",
       "Low", "automated",
       checks=[chk("capacity.system_drive_free_pct", "gte", 15,
                   "System drive at least 15% free"),
               chk("capacity.memory_free_pct", "gte", 10, "At least 10% memory headroom")],
       remediation=[
           "Free or extend the system volume to keep at least 15% headroom.",
           "Configure alerting on disk, memory and CPU thresholds.",
           "Produce capacity forecasts for critical systems and plan upgrades ahead of exhaustion."]))

A(ctrl("A.8.7", "Protection against malware", TEC,
       "Protection against malware is implemented and supported by user awareness.",
       "High", "automated",
       checks=[chk("endpoint_protection.antivirus_enabled", "truthy", "Anti-malware installed and on"),
               chk("endpoint_protection.realtime_protection", "truthy", "Real-time protection on"),
               chk("endpoint_protection.signature_age_days", "lte", 3,
                   "Signatures updated within 3 days"),
               chk("endpoint_protection.tamper_protection", "truthy", "Tamper protection on"),
               chk("endpoint_protection.asr_rules_enabled", "gte", 5,
                   "At least 5 attack surface reduction rules enforced")],
       remediation=[
           "Enable Microsoft Defender Antivirus with real-time and cloud-delivered protection.",
           "Ensure signature updates run at least daily; investigate devices >3 days stale.",
           "Turn on Tamper Protection so the agent cannot be disabled locally.",
           "Enable the recommended Attack Surface Reduction rules in Block mode.",
           "Combine with user phishing awareness training."]))

A(ctrl("A.8.8", "Management of technical vulnerabilities", TEC,
       "Information about technical vulnerabilities is obtained and exposure evaluated and addressed.",
       "High", "automated",
       checks=[chk("patching.missing_critical_patches", "lte", 0,
                   "No missing critical / security updates"),
               chk("patching.last_patch_install_days", "lte", 35,
                   "Patched within the last 35 days"),
               chk("patching.os_supported", "truthy", "OS still receiving vendor updates"),
               chk("patching.auto_update_enabled", "truthy", "Automatic updates enabled")],
       remediation=[
           "Install all outstanding critical and security updates immediately.",
           "Define patch SLAs (critical 7 days, high 14 days, others 35 days) and measure against them.",
           "Enable automatic updates or an equivalent managed patching service (WSUS/Intune/SCCM).",
           "Upgrade or decommission any operating system past end-of-support.",
           "Run authenticated vulnerability scans monthly and track findings to closure."]))

A(ctrl("A.8.9", "Configuration management", TEC,
       "Configurations of hardware, software, services and networks are established and monitored.",
       "High", "automated",
       checks=[chk("endpoint_protection.secure_boot_enabled", "truthy", "Secure Boot enabled"),
               chk("encryption.smbv1_enabled", "falsy", "SMBv1 removed"),
               chk("services.telnet_installed", "falsy", "Telnet client/server not installed"),
               chk("configuration.baseline_drift_count", "lte", 5,
                   "Baseline drift within tolerance"),
               chk("endpoint_protection.uac_enabled", "truthy", "UAC enabled")],
       remediation=[
           "Adopt a documented hardening baseline (CIS Benchmark or Microsoft Security Baseline).",
           "Enable Secure Boot in UEFI firmware.",
           "Remove the SMB 1.0/CIFS and Telnet Windows features.",
           "Deploy the baseline via GPO or Intune and monitor drift continuously.",
           "Require change approval before deviating from the baseline."]))

A(ctrl("A.8.10", "Information deletion", TEC,
       "Information stored in systems and devices is deleted when no longer required.",
       "Medium", "hybrid", attestation="deletion_procedure",
       checks=[chk("data.retention_policy_configured", "truthy",
                   "Automated retention / deletion policy configured")],
       remediation=[
           "Configure retention labels or policies that delete data at end of life automatically.",
           "Use secure deletion (cryptographic erase or multi-pass) for classified data.",
           "Record deletions for regulated data to evidence compliance."]))

A(ctrl("A.8.11", "Data masking", TEC,
       "Data masking is used in line with the access control and business requirements.",
       "Medium", "manual", attestation="data_masking_applied",
       remediation=[
           "Mask or tokenise sensitive fields in non-production environments.",
           "Apply dynamic data masking in databases for users without a need to see full values.",
           "Limit who can view unmasked data and log those views."]))

A(ctrl("A.8.12", "Data leakage prevention", TEC,
       "Data leakage prevention measures are applied to systems and networks handling sensitive data.",
       "High", "automated",
       checks=[chk("asset.dlp_enabled", "truthy", "DLP policy active"),
               chk("endpoint_protection.usb_storage_blocked", "truthy",
                   "Removable media egress controlled"),
               chk("endpoint_protection.network_protection_enabled", "truthy",
                   "Network protection / egress filtering on")],
       remediation=[
           "Deploy endpoint and cloud DLP policies targeting your classified data types.",
           "Restrict removable media and cloud sync clients for sensitive endpoints.",
           "Enable Defender Network Protection and block known exfiltration destinations.",
           "Start DLP in audit mode, tune, then move to block."]))

A(ctrl("A.8.13", "Information backup", TEC,
       "Backup copies of information, software and systems are maintained and regularly tested.",
       "High", "automated",
       checks=[chk("backup.backup_configured", "truthy", "Backup configured"),
               chk("backup.last_backup_days", "lte", 7, "Backup completed in last 7 days"),
               chk("backup.backup_encrypted", "truthy", "Backups encrypted"),
               chk("backup.offsite_or_immutable", "truthy", "Off-site or immutable copy held"),
               chk("backup.restore_tested_days", "lte", 180,
                   "Restore tested within 180 days")],
       remediation=[
           "Implement the 3-2-1-1 rule: 3 copies, 2 media types, 1 off-site, 1 immutable/offline.",
           "Schedule backups to meet the defined RPO and alert on job failure.",
           "Encrypt backup data at rest and in transit; protect the backup credentials separately.",
           "Perform and document a restore test every 6 months."]))

A(ctrl("A.8.14", "Redundancy of information processing facilities", TEC,
       "Processing facilities are implemented with sufficient redundancy to meet availability needs.",
       "Medium", "hybrid", attestation="redundancy_designed",
       checks=[chk("backup.shadow_copies_enabled", "truthy",
                   "Volume Shadow Copies enabled for rapid recovery")],
       remediation=[
           "Enable Volume Shadow Copy Service on data volumes for fast local rollback.",
           "Design N+1 redundancy for components supporting critical services.",
           "Test failover of redundant components at least annually."]))

A(ctrl("A.8.15", "Logging", TEC,
       "Logs recording activities, exceptions, faults and other relevant events are produced and retained.",
       "High", "automated",
       checks=[chk("logging.logging_level", "in", ["Standard", "Verbose"],
                   "Logging level at least Standard"),
               chk("logging.audit_logon_events", "contains", "Failure",
                   "Logon failures audited"),
               chk("logging.audit_account_management", "contains", "Success",
                   "Account management audited"),
               chk("logging.audit_policy_change", "contains", "Success",
                   "Policy changes audited"),
               chk("logging.audit_privilege_use", "contains", "Failure",
                   "Privilege use audited"),
               chk("logging.security_log_retention_days", "gte", 90,
                   "Logs retained >= 90 days"),
               chk("logging.powershell_scriptblock_logging", "truthy",
                   "PowerShell script block logging on"),
               chk("logging.command_line_auditing", "truthy",
                   "Process command line auditing on")],
       remediation=[
           "Enable Advanced Audit Policy for Logon, Account Management, Policy Change, Privilege Use and Object Access.",
           "Raise the Security log to 1 GB+ and retain at least 90 days (12 months preferred).",
           "Enable PowerShell Script Block Logging and Module Logging.",
           "Enable 'Include command line in process creation events' (Event ID 4688).",
           "Protect logs from modification by forwarding them off-host."]))

A(ctrl("A.8.16", "Monitoring activities", TEC,
       "Networks, systems and applications are monitored for anomalous behaviour and action is taken.",
       "High", "automated",
       checks=[chk("logging.log_forwarding_enabled", "truthy",
                   "Log forwarding to SIEM / central collector"),
               chk("endpoint_protection.edr_enabled", "truthy",
                   "EDR sensor installed and reporting"),
               chk("endpoint_protection.cloud_protection_enabled", "truthy",
                   "Cloud-delivered detection enabled")],
       remediation=[
           "Configure Windows Event Forwarding or a SIEM agent on every in-scope host.",
           "Deploy an EDR product with alerting routed to a monitored queue.",
           "Define detection use cases and alert thresholds for your top risks.",
           "Document who monitors alerts and the response time expectation."]))

A(ctrl("A.8.17", "Clock synchronization", TEC,
       "Clocks are synchronised to approved time sources.",
       "Medium", "automated",
       checks=[chk("logging.time_sync_configured", "truthy", "Time service configured"),
               chk("logging.time_offset_seconds", "lte", 5,
                   "Clock within 5 seconds of the time source"),
               chk("logging.ntp_server", "non_empty", "Authoritative time source set")],
       remediation=[
           "Point the Windows Time service at an authoritative internal or trusted external NTP source.",
           "Set the service to start automatically and verify with 'w32tm /query /status'.",
           "Alert when offset exceeds a few seconds — log correlation depends on it."]))

A(ctrl("A.8.18", "Use of privileged utility programs", TEC,
       "Use of utility programs capable of overriding controls is restricted and tightly controlled.",
       "High", "automated",
       checks=[chk("endpoint_protection.applocker_or_wdac_enabled", "truthy",
                   "Application control (AppLocker/WDAC) enforcing"),
               chk("logging.powershell_scriptblock_logging", "truthy",
                   "PowerShell activity logged"),
               chk("services.remote_registry_running", "falsy",
                   "Remote Registry service not running")],
       remediation=[
           "Enforce AppLocker or WDAC policies restricting administrative and hacking utilities.",
           "Enable PowerShell Constrained Language Mode for non-administrators.",
           "Disable the Remote Registry service unless a documented need exists.",
           "Log and review every use of privileged utilities."]))

A(ctrl("A.8.19", "Installation of software on operational systems", TEC,
       "Procedures securely manage software installation on operational systems.",
       "Medium", "automated",
       checks=[chk("asset.unauthorized_software_count", "lte", 0,
                   "No unauthorised software installed"),
               chk("endpoint_protection.applocker_or_wdac_enabled", "truthy",
                   "Software installation restricted"),
               chk("identity.standard_users_cannot_install", "truthy",
                   "Standard users cannot install software")],
       remediation=[
           "Maintain an approved software catalogue and remove anything outside it.",
           "Prevent standard users from installing software (no local admin, restricted MSI policy).",
           "Deploy software only through a managed distribution channel with change approval.",
           "Verify digital signatures before deployment."]))

A(ctrl("A.8.20", "Networks security", TEC,
       "Networks and network devices are secured, managed and controlled.",
       "High", "automated",
       checks=[chk("endpoint_protection.firewall_domain", "truthy", "Firewall on: Domain profile"),
               chk("endpoint_protection.firewall_private", "truthy", "Firewall on: Private profile"),
               chk("endpoint_protection.firewall_public", "truthy", "Firewall on: Public profile"),
               chk("endpoint_protection.inbound_default_block", "truthy",
                   "Default inbound action is Block"),
               chk("network.risky_ports_open_count", "lte", 0,
                   "No high-risk ports listening (135/139/445/3389/23/21 exposed)")],
       remediation=[
           "Enable Windows Defender Firewall on all three profiles with default inbound Block.",
           "Close or firewall-restrict legacy and management ports (21, 23, 135, 139, 445, 3389).",
           "Restrict RDP to a jump host or VPN-only source range.",
           "Review firewall rules quarterly and remove unused ones."]))

A(ctrl("A.8.21", "Security of network services", TEC,
       "Security mechanisms, service levels and requirements of network services are identified and monitored.",
       "High", "automated",
       checks=[chk("encryption.tls10_enabled", "falsy", "TLS 1.0 disabled"),
               chk("encryption.tls11_enabled", "falsy", "TLS 1.1 disabled"),
               chk("encryption.tls12_enabled", "truthy", "TLS 1.2 enabled"),
               chk("network.llmnr_disabled", "truthy", "LLMNR disabled"),
               chk("network.netbios_enabled", "falsy", "NetBIOS over TCP/IP disabled")],
       remediation=[
           "Disable SSL 2.0/3.0, TLS 1.0 and TLS 1.1 in the SCHANNEL registry keys; enable TLS 1.2/1.3.",
           "Disable LLMNR and NetBIOS over TCP/IP to prevent name-poisoning relay attacks.",
           "Agree security requirements and SLAs with network service providers in writing.",
           "Monitor the availability and integrity of critical network services."]))

A(ctrl("A.8.22", "Segregation of networks", TEC,
       "Groups of information services, users and systems are segregated in networks.",
       "Medium", "hybrid", attestation="network_segmentation",
       checks=[chk("network.host_firewall_isolation", "truthy",
                   "Host-based isolation rules present")],
       remediation=[
           "Separate user, server, management and guest traffic into distinct VLANs/subnets.",
           "Filter between segments with an explicit allow-list.",
           "Place OT, legacy and unsupported systems in isolated segments.",
           "Use host-based firewall rules as a second layer of isolation."]))

A(ctrl("A.8.23", "Web filtering", TEC,
       "Access to external websites is managed to reduce exposure to malicious content.",
       "Medium", "automated",
       checks=[chk("endpoint_protection.network_protection_enabled", "truthy",
                   "Defender Network Protection / web protection on"),
               chk("network.dns_filtering_enabled", "truthy",
                   "Filtered/protective DNS resolver in use")],
       remediation=[
           "Enable Defender Network Protection in Block mode (or a secure web gateway).",
           "Point clients at a protective DNS service that blocks malicious domains.",
           "Block known-risky categories and newly registered domains.",
           "Publish the filtering policy and an exception request process."]))

A(ctrl("A.8.24", "Use of cryptography", TEC,
       "Rules for effective use of cryptography, including key management, are defined and implemented.",
       "High", "automated",
       checks=[chk("encryption.disk_encryption_enabled", "truthy", "Data at rest encrypted"),
               chk("encryption.disk_encryption_type", "in", ["XtsAes256", "XtsAes128", "AES-256"],
                   "Approved encryption algorithm in use"),
               chk("encryption.unencrypted_volume_count", "lte", 0,
                   "No unencrypted fixed volumes"),
               chk("encryption.key_protector_present", "truthy",
                   "Encryption key protector (TPM/recovery key) configured"),
               chk("encryption.tls12_enabled", "truthy", "Strong TLS available for data in transit")],
       remediation=[
           "Encrypt every fixed volume with BitLocker XTS-AES-256.",
           "Escrow recovery keys to Active Directory or Entra ID and verify escrow succeeded.",
           "Publish a cryptography policy naming approved algorithms, key lengths and lifetimes.",
           "Define key generation, storage, rotation, and destruction procedures."]))

A(ctrl("A.8.25", "Secure development life cycle", TEC,
       "Rules for the secure development of software and systems are established and applied.",
       "Medium", "manual", attestation="secure_sdlc",
       remediation=[
           "Document an SDLC with security gates at design, build, test and release.",
           "Require threat modelling for new or materially changed services.",
           "Train developers annually on secure coding for your technology stack."]))

A(ctrl("A.8.26", "Application security requirements", TEC,
       "Security requirements are identified, specified and approved when developing or acquiring applications.",
       "Medium", "manual", attestation="app_security_requirements",
       remediation=[
           "Define a baseline set of application security requirements (authn, authz, logging, crypto, input validation).",
           "Include them in requirements documents and vendor RFPs.",
           "Verify each requirement before release sign-off."]))

A(ctrl("A.8.27", "Secure system architecture and engineering principles", TEC,
       "Principles for engineering secure systems are established, documented and applied.",
       "Medium", "manual", attestation="secure_architecture_principles",
       remediation=[
           "Adopt and publish principles: least privilege, defence in depth, secure defaults, fail secure, zero trust.",
           "Require an architecture review against these principles for significant changes.",
           "Record deviations as accepted risks with an owner and expiry."]))

A(ctrl("A.8.28", "Secure coding", TEC,
       "Secure coding principles are applied to software development.",
       "Medium", "manual", attestation="secure_coding_standards",
       remediation=[
           "Publish a secure coding standard mapped to OWASP Top 10 / ASVS.",
           "Run SAST and software composition analysis in CI and fail builds on high findings.",
           "Require peer review of security-relevant code and scan for hard-coded secrets."]))

A(ctrl("A.8.29", "Security testing in development and acceptance", TEC,
       "Security testing processes are defined and implemented in the development lifecycle.",
       "Medium", "manual", attestation="security_testing_performed",
       remediation=[
           "Define required test types per release risk (SAST, DAST, dependency scan, pen test).",
           "Set acceptance thresholds that block release when unmet.",
           "Retain test evidence for audit and retest fixes before closure."]))

A(ctrl("A.8.30", "Outsourced development", TEC,
       "Outsourced development activity is directed, monitored and reviewed.",
       "Low", "manual", attestation="outsourced_dev_controlled",
       remediation=[
           "Impose your secure coding and testing standards contractually on the supplier.",
           "Require evidence of security testing and the right to independently test.",
           "Escrow source code and verify IP ownership terms."]))

A(ctrl("A.8.31", "Separation of development, test and production environments", TEC,
       "Development, test and production environments are separated and secured.",
       "Medium", "manual", attestation="environments_separated",
       remediation=[
           "Run development, test and production on separate infrastructure and credentials.",
           "Prevent developers from holding standing production access.",
           "Control and log any promotion of code or data between environments."]))

A(ctrl("A.8.32", "Change management", TEC,
       "Changes to information processing facilities and systems are subject to change management.",
       "High", "hybrid", attestation="change_management_process",
       checks=[chk("patching.pending_reboot", "falsy",
                   "No pending reboot leaving changes half-applied")],
       remediation=[
           "Operate a change management process with risk assessment, approval, testing and rollback plans.",
           "Complete pending reboots in a controlled window so changes take effect.",
           "Record emergency changes retrospectively within an agreed timeframe.",
           "Review change records for unauthorised changes periodically."]))

A(ctrl("A.8.33", "Test information", TEC,
       "Test information is appropriately selected, protected and managed.",
       "Low", "manual", attestation="test_data_protected",
       remediation=[
           "Prohibit copying live personal or confidential data into test environments.",
           "Where live data is unavoidable, mask it and apply production-grade controls.",
           "Log and approve every copy of production data and delete it when testing ends."]))

A(ctrl("A.8.34", "Protection of information systems during audit testing", TEC,
       "Audit tests on operational systems are planned and agreed to minimise disruption.",
       "Low", "hybrid", attestation="audit_testing_controlled",
       checks=[chk("logging.audit_object_access", "contains", "Success",
                   "Read-only audit activity is itself auditable")],
       remediation=[
           "Agree audit scope, timing and read-only access with system owners in advance.",
           "Use read-only accounts for audit data collection and log all audit access.",
           "Schedule intrusive testing outside business-critical windows."]))

# --------------------------------------------------------------------------
# Assemble and write
# --------------------------------------------------------------------------

BASELINE = {
    "framework": "ISO/IEC 27001:2022 — Annex A",
    "version": "1.0.0",
    "generated_by": "ISO 27001 Compliance Auditor",
    "themes": {
        "Organizational": "A.5 — 37 controls",
        "People": "A.6 — 8 controls",
        "Physical": "A.7 — 14 controls",
        "Technological": "A.8 — 34 controls",
    },
    "severity_weights": {"High": 5, "Medium": 3, "Low": 1},
    "controls": CONTROLS,
}

if __name__ == "__main__":
    here = os.path.dirname(os.path.abspath(__file__))
    out = os.path.join(here, "iso27001_baseline.json")

    ids = [c["id"] for c in CONTROLS]
    assert len(ids) == len(set(ids)), "Duplicate control IDs detected"
    assert len(CONTROLS) == 93, f"Expected 93 controls, built {len(CONTROLS)}"

    with open(out, "w", encoding="utf-8") as fh:
        json.dump(BASELINE, fh, indent=2, ensure_ascii=False)

    by_theme = {}
    for c in CONTROLS:
        by_theme[c["theme"]] = by_theme.get(c["theme"], 0) + 1
    print(f"Wrote {out}")
    print(f"Total controls : {len(CONTROLS)}")
    for k, v in by_theme.items():
        print(f"  {k:<16} {v}")
    print(f"Automated      : {sum(1 for c in CONTROLS if c['mode'] == 'automated')}")
    print(f"Hybrid         : {sum(1 for c in CONTROLS if c['mode'] == 'hybrid')}")
    print(f"Manual         : {sum(1 for c in CONTROLS if c['mode'] == 'manual')}")
