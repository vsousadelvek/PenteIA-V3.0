"""
apt_engine.py — APT Group Profiles and Simulation Plans for PenteIA V4.0

Defines known APT group profiles and exposes functions for listing groups,
retrieving group details, and generating ordered simulation plans based on
each group's kill chain.
"""

from __future__ import annotations


APT_GROUPS: dict[str, dict] = {
    "lazarus": {
        "id": "lazarus",
        "name": "Lazarus Group",
        "aliases": ["HIDDEN COBRA", "Guardians of Peace", "ZINC", "NICKEL ACADEMY"],
        "origin_country": "North Korea",
        "target_sectors": ["financial", "cryptocurrency", "defense", "media"],
        "description": (
            "Lazarus Group is a North Korean state-sponsored threat actor believed to operate "
            "under the Reconnaissance General Bureau (RGB). Active since at least 2009, the group "
            "is responsible for major financial heists including the 2016 Bangladesh Bank robbery "
            "and numerous cryptocurrency exchange attacks. They blend financial motivation with "
            "espionage and destructive capabilities."
        ),
        "kill_chain": [
            {
                "order": 1,
                "technique_id": "T1598",
                "name": "Phishing for Information",
                "tactic": "Reconnaissance",
                "description": (
                    "Conduct spear-phishing campaigns to harvest credentials or gather intelligence "
                    "about target personnel, infrastructure, and systems prior to intrusion."
                ),
            },
            {
                "order": 2,
                "technique_id": "T1566.001",
                "name": "Spearphishing Attachment",
                "tactic": "Initial Access",
                "description": (
                    "Deliver malicious documents (Word, Excel, HWP files) via targeted spear-phishing "
                    "emails to specific individuals within the target organization."
                ),
            },
            {
                "order": 3,
                "technique_id": "T1059.005",
                "name": "Command and Scripting Interpreter: Visual Basic",
                "tactic": "Execution",
                "description": (
                    "Execute malicious VBA macros embedded in Office documents to download and run "
                    "additional payloads or establish persistence on the victim host."
                ),
            },
            {
                "order": 4,
                "technique_id": "T1055",
                "name": "Process Injection",
                "tactic": "Defense Evasion / Privilege Escalation",
                "description": (
                    "Inject malicious code into legitimate running processes (e.g., explorer.exe, "
                    "svchost.exe) to evade detection and execute with elevated privileges."
                ),
            },
            {
                "order": 5,
                "technique_id": "T1005",
                "name": "Data from Local System",
                "tactic": "Collection",
                "description": (
                    "Search and collect sensitive files, credentials, financial data, and "
                    "cryptocurrency wallet information from the local file system."
                ),
            },
            {
                "order": 6,
                "technique_id": "T1041",
                "name": "Exfiltration Over C2 Channel",
                "tactic": "Exfiltration",
                "description": (
                    "Exfiltrate collected data over the existing command-and-control channel, "
                    "blending exfiltration traffic with normal C2 communications."
                ),
            },
            {
                "order": 7,
                "technique_id": "T1486",
                "name": "Data Encrypted for Impact",
                "tactic": "Impact",
                "description": (
                    "Deploy ransomware or destructive wipers to encrypt or destroy data on "
                    "compromised systems, causing operational disruption or as a distraction "
                    "during financial theft operations."
                ),
            },
        ],
    },

    "apt28": {
        "id": "apt28",
        "name": "APT28",
        "aliases": ["Fancy Bear", "Sofacy", "STRONTIUM", "Pawn Storm", "Sednit", "Tsar Team"],
        "origin_country": "Russia",
        "target_sectors": ["government", "military", "defense", "political organizations", "aerospace"],
        "description": (
            "APT28 (Fancy Bear) is a Russian military intelligence (GRU Unit 26165) threat actor "
            "active since at least 2004. Known for high-profile intrusions including the 2016 DNC "
            "hack, attacks against NATO and EU governments, and the World Anti-Doping Agency (WADA). "
            "The group specializes in credential theft, strategic espionage, and influence operations."
        ),
        "kill_chain": [
            {
                "order": 1,
                "technique_id": "T1595",
                "name": "Active Scanning",
                "tactic": "Reconnaissance",
                "description": (
                    "Conduct active scanning of target infrastructure to identify open ports, "
                    "services, and vulnerabilities before launching attacks."
                ),
            },
            {
                "order": 2,
                "technique_id": "T1598",
                "name": "Phishing for Information",
                "tactic": "Reconnaissance",
                "description": (
                    "Launch credential-harvesting phishing campaigns using spoofed login pages "
                    "mimicking legitimate services (Gmail, corporate VPNs, webmail portals)."
                ),
            },
            {
                "order": 3,
                "technique_id": "T1566",
                "name": "Phishing",
                "tactic": "Initial Access",
                "description": (
                    "Send targeted phishing emails with malicious links or attachments to "
                    "gain initial foothold in the target environment."
                ),
            },
            {
                "order": 4,
                "technique_id": "T1078",
                "name": "Valid Accounts",
                "tactic": "Defense Evasion / Persistence",
                "description": (
                    "Use harvested or stolen credentials to authenticate to legitimate services, "
                    "VPNs, and cloud platforms, avoiding detection by blending with normal activity."
                ),
            },
            {
                "order": 5,
                "technique_id": "T1021",
                "name": "Remote Services",
                "tactic": "Lateral Movement",
                "description": (
                    "Move laterally through the network using legitimate remote services such as "
                    "RDP, SSH, and SMB with valid credentials obtained during earlier phases."
                ),
            },
            {
                "order": 6,
                "technique_id": "T1560",
                "name": "Archive Collected Data",
                "tactic": "Collection",
                "description": (
                    "Compress and archive sensitive documents, emails, and intelligence data "
                    "to prepare for exfiltration while minimizing transfer size."
                ),
            },
            {
                "order": 7,
                "technique_id": "T1041",
                "name": "Exfiltration Over C2 Channel",
                "tactic": "Exfiltration",
                "description": (
                    "Exfiltrate archived data through established C2 channels, often using "
                    "encrypted HTTPS traffic to blend with legitimate web traffic."
                ),
            },
        ],
    },

    "cobalt_group": {
        "id": "cobalt_group",
        "name": "Cobalt Group",
        "aliases": ["COBALT", "Gold Kingswood", "Cobalt Gang"],
        "origin_country": "Eastern Europe",
        "target_sectors": ["banking", "financial services", "ATM networks", "payment systems"],
        "description": (
            "Cobalt Group is a financially motivated threat actor primarily targeting banks and "
            "financial institutions across Europe, CIS countries, and Southeast Asia. The group "
            "is responsible for ATM jackpotting attacks and SWIFT-based fraud resulting in hundreds "
            "of millions of dollars in losses. They leverage Cobalt Strike and custom malware for "
            "network compromise and fund theft."
        ),
        "kill_chain": [
            {
                "order": 1,
                "technique_id": "T1566.001",
                "name": "Spearphishing Attachment",
                "tactic": "Initial Access",
                "description": (
                    "Send targeted spear-phishing emails with malicious Microsoft Office documents "
                    "to bank employees, particularly those in finance and IT departments."
                ),
            },
            {
                "order": 2,
                "technique_id": "T1055",
                "name": "Process Injection",
                "tactic": "Defense Evasion / Privilege Escalation",
                "description": (
                    "Inject Cobalt Strike shellcode or custom payloads into legitimate processes "
                    "to evade endpoint detection and maintain stealthy execution."
                ),
            },
            {
                "order": 3,
                "technique_id": "T1059",
                "name": "Command and Scripting Interpreter",
                "tactic": "Execution",
                "description": (
                    "Execute PowerShell, CMD, and scripting languages to run payloads, conduct "
                    "reconnaissance, and establish persistence on compromised banking systems."
                ),
            },
            {
                "order": 4,
                "technique_id": "T1003",
                "name": "OS Credential Dumping",
                "tactic": "Credential Access",
                "description": (
                    "Dump credentials from LSASS memory and SAM database using Mimikatz or "
                    "similar tools to enable lateral movement to high-value banking systems."
                ),
            },
            {
                "order": 5,
                "technique_id": "T1021.002",
                "name": "Remote Services: SMB/Windows Admin Shares",
                "tactic": "Lateral Movement",
                "description": (
                    "Move laterally to ATM controllers, SWIFT terminals, and banking middleware "
                    "servers using compromised credentials over SMB administrative shares."
                ),
            },
            {
                "order": 6,
                "technique_id": "T1105",
                "name": "Ingress Tool Transfer",
                "tactic": "Command and Control",
                "description": (
                    "Transfer ATM jackpotting tools (e.g., Tyupkin, Ploutus) and SWIFT fraud "
                    "scripts to compromised banking infrastructure systems."
                ),
            },
            {
                "order": 7,
                "technique_id": "T1486",
                "name": "Data Encrypted for Impact",
                "tactic": "Impact",
                "description": (
                    "Deploy ransomware or destructive payloads as a distraction or final impact "
                    "phase after completing financial fraud operations."
                ),
            },
        ],
    },

    "muddywater": {
        "id": "muddywater",
        "name": "MuddyWater",
        "aliases": ["MERCURY", "Static Kitten", "Seedworm", "TEMP.Zagros"],
        "origin_country": "Iran",
        "target_sectors": ["government", "telecommunications", "defense", "oil and gas", "academia"],
        "description": (
            "MuddyWater is an Iranian state-sponsored threat actor attributed to Iran's Ministry "
            "of Intelligence and Security (MOIS). Active since 2017, they target government and "
            "critical sector organizations in the Middle East, Europe, and North America. The group "
            "relies heavily on spear-phishing and living-off-the-land techniques, frequently using "
            "PowerShell, Python, and legitimate remote administration tools."
        ),
        "kill_chain": [
            {
                "order": 1,
                "technique_id": "T1566",
                "name": "Phishing",
                "tactic": "Initial Access",
                "description": (
                    "Deliver spear-phishing emails with malicious attachments or links, often "
                    "using macro-enabled documents or links to download first-stage payloads."
                ),
            },
            {
                "order": 2,
                "technique_id": "T1059.001",
                "name": "Command and Scripting Interpreter: PowerShell",
                "tactic": "Execution",
                "description": (
                    "Execute PowerShell scripts to download additional payloads, perform "
                    "reconnaissance, and establish persistence while evading traditional AV detection."
                ),
            },
            {
                "order": 3,
                "technique_id": "T1547",
                "name": "Boot or Logon Autostart Execution",
                "tactic": "Persistence",
                "description": (
                    "Establish persistence via registry run keys, scheduled tasks, or startup "
                    "folder entries to survive reboots on compromised government systems."
                ),
            },
            {
                "order": 4,
                "technique_id": "T1071",
                "name": "Application Layer Protocol",
                "tactic": "Command and Control",
                "description": (
                    "Use HTTP/HTTPS-based C2 communication protocols, often leveraging legitimate "
                    "cloud services and web platforms to blend C2 traffic with normal web activity."
                ),
            },
            {
                "order": 5,
                "technique_id": "T1048",
                "name": "Exfiltration Over Alternative Protocol",
                "tactic": "Exfiltration",
                "description": (
                    "Exfiltrate collected intelligence data over alternative protocols such as "
                    "DNS tunneling or email to avoid detection by network security controls."
                ),
            },
        ],
    },

    "sandworm": {
        "id": "sandworm",
        "name": "Sandworm Team",
        "aliases": ["VOODOO BEAR", "Telebots", "Iron Viking", "BlackEnergy Group", "Quedagh"],
        "origin_country": "Russia",
        "target_sectors": [
            "critical infrastructure", "industrial control systems", "energy", "water utilities",
            "transportation", "government"
        ],
        "description": (
            "Sandworm is a Russian GRU (Unit 74455) threat actor known for the most destructive "
            "cyberattacks ever recorded, including the 2015 and 2016 Ukrainian power grid attacks, "
            "the NotPetya wiper campaign (2017), and attacks on the 2018 Winter Olympics. The group "
            "specializes in attacks against industrial control systems (ICS/SCADA) and critical "
            "infrastructure, using custom malware including BlackEnergy, Industroyer, and NotPetya."
        ),
        "kill_chain": [
            {
                "order": 1,
                "technique_id": "T1190",
                "name": "Exploit Public-Facing Application",
                "tactic": "Initial Access",
                "description": (
                    "Exploit vulnerabilities in internet-facing applications, VPNs, and remote "
                    "access systems to gain initial access to critical infrastructure networks."
                ),
            },
            {
                "order": 2,
                "technique_id": "T1059",
                "name": "Command and Scripting Interpreter",
                "tactic": "Execution",
                "description": (
                    "Execute scripts and commands to deploy ICS-specific malware (Industroyer/Crashoverride), "
                    "conduct reconnaissance of OT networks, and manipulate industrial control systems."
                ),
            },
            {
                "order": 3,
                "technique_id": "T1485",
                "name": "Data Destruction",
                "tactic": "Impact",
                "description": (
                    "Deploy destructive wipers (NotPetya, KillDisk) to destroy data on compromised "
                    "systems, rendering them inoperable and causing widespread operational disruption."
                ),
            },
            {
                "order": 4,
                "technique_id": "T1490",
                "name": "Inhibit System Recovery",
                "tactic": "Impact",
                "description": (
                    "Delete shadow copies, disable backup services, and corrupt recovery mechanisms "
                    "to prevent victims from restoring systems after destructive attacks."
                ),
            },
            {
                "order": 5,
                "technique_id": "T1499",
                "name": "Endpoint Denial of Service",
                "tactic": "Impact",
                "description": (
                    "Execute denial of service attacks against critical infrastructure endpoints "
                    "to disrupt power grids, industrial processes, and essential services."
                ),
            },
        ],
    },

    "lapsus": {
        "id": "lapsus",
        "name": "Lapsus$",
        "aliases": ["DEV-0537", "LAPSUS$"],
        "origin_country": "LATAM / Global",
        "target_sectors": [
            "technology", "gaming", "telecommunications", "data extortion",
            "software supply chain", "cloud services"
        ],
        "description": (
            "Lapsus$ is a loosely organized, financially motivated extortion group with members "
            "believed to be based in Brazil and the UK. Active from 2021 to 2022, they compromised "
            "high-profile targets including Microsoft, NVIDIA, Okta, Samsung, Uber, and Rockstar Games. "
            "The group relied heavily on social engineering, SIM swapping, and insider recruitment "
            "rather than sophisticated technical malware, demonstrating the effectiveness of identity-based attacks."
        ),
        "kill_chain": [
            {
                "order": 1,
                "technique_id": "T1078",
                "name": "Valid Accounts",
                "tactic": "Initial Access / Defense Evasion",
                "description": (
                    "Obtain valid credentials through social engineering, SIM swapping, purchasing "
                    "credentials from dark web markets, or recruiting malicious insiders within "
                    "target organizations to gain legitimate access."
                ),
            },
            {
                "order": 2,
                "technique_id": "T1539",
                "name": "Steal Web Session Cookie",
                "tactic": "Credential Access",
                "description": (
                    "Steal authenticated session tokens and cookies from employee browsers or "
                    "endpoint devices to bypass multi-factor authentication controls."
                ),
            },
            {
                "order": 3,
                "technique_id": "T1213",
                "name": "Data from Information Repositories",
                "tactic": "Collection",
                "description": (
                    "Access and harvest sensitive data from internal collaboration tools, "
                    "code repositories (GitHub, GitLab, Azure DevOps), wikis, and document "
                    "management platforms such as SharePoint and Confluence."
                ),
            },
            {
                "order": 4,
                "technique_id": "T1537",
                "name": "Transfer Data to Cloud Account",
                "tactic": "Exfiltration",
                "description": (
                    "Exfiltrate stolen source code, credentials, and sensitive data to attacker-controlled "
                    "cloud storage accounts (Telegram, Mega.nz, personal cloud storage) for extortion leverage."
                ),
            },
            {
                "order": 5,
                "technique_id": "T1657",
                "name": "Financial Theft",
                "tactic": "Impact",
                "description": (
                    "Extort victims by threatening to publicly release stolen source code, "
                    "proprietary data, and credentials unless a ransom is paid. Publicly leak "
                    "data on Telegram to pressure non-compliant victims."
                ),
            },
        ],
    },
}


def list_apt_groups() -> list[dict]:
    """Return summary information for all APT groups, excluding full kill_chain details."""
    summaries = []
    for group in APT_GROUPS.values():
        summaries.append({
            "id": group["id"],
            "name": group["name"],
            "aliases": group["aliases"],
            "origin_country": group["origin_country"],
            "target_sectors": group["target_sectors"],
            "description": group["description"],
            "kill_chain_length": len(group["kill_chain"]),
        })
    return summaries


def get_apt_group(group_id: str) -> dict | None:
    """Return the full profile for a given APT group ID, or None if not found."""
    return APT_GROUPS.get(group_id)


def get_apt_simulation_plan(group_id: str) -> list[dict]:
    """
    Return the ordered kill chain simulation plan for a given APT group.

    Returns an empty list if the group_id is not recognized.
    """
    group = APT_GROUPS.get(group_id)
    if group is None:
        return []
    return sorted(group["kill_chain"], key=lambda step: step["order"])
