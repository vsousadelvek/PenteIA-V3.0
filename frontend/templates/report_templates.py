REPORT_TEMPLATES = {
    "penetration_test": {
        "title": "Penetration Test Report",
        "description": "Comprehensive penetration testing report",
        "defaults": {
            "client": "Client Name",
            "test_date": "{{ test_date }}",
            "duration": "1 week",
            "scope": "Web application, API endpoints",
            "vulnerabilities_found": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
        },
        "fields": [
            "client",
            "test_date",
            "duration",
            "scope",
            "vulnerabilities_found",
            "critical",
            "high",
            "medium",
            "low",
        ],
        "sections": [
            {
                "name": "Executive Summary",
                "template": """
This penetration test was conducted for {{ client }} on {{ test_date }}.
The assessment lasted {{ duration }} and covered {{ scope }}.

Key Findings:
- Total Vulnerabilities Found: {{ vulnerabilities_found }}
- Critical: {{ critical }}
- High: {{ high }}
- Medium: {{ medium }}
- Low: {{ low }}
""",
            },
            {
                "name": "Methodology",
                "template": """
The penetration testing was conducted following industry best practices and OWASP guidelines.
Testing methodologies included:
- Reconnaissance and information gathering
- Network scanning and enumeration
- Vulnerability assessment
- Exploitation and post-exploitation
- Report documentation
""",
            },
            {
                "name": "Findings Summary",
                "template": """
A total of {{ vulnerabilities_found }} vulnerabilities were identified during the assessment.
The severity distribution is as follows:
- Critical: {{ critical }} issues requiring immediate attention
- High: {{ high }} issues with significant impact
- Medium: {{ medium }} issues needing attention
- Low: {{ low }} informational findings
""",
            },
        ],
    },
    "executive_summary": {
        "title": "Executive Summary",
        "description": "High-level summary for management",
        "defaults": {
            "organization": "Organization Name",
            "assessment_date": "{{ assessment_date }}",
            "overall_risk": "Medium",
            "recommendations": "Implement recommended remediation steps",
        },
        "fields": ["organization", "assessment_date", "overall_risk", "recommendations"],
        "sections": [
            {
                "name": "Overview",
                "template": """
Assessment Overview
Organization: {{ organization }}
Assessment Date: {{ assessment_date }}
Overall Risk Level: {{ overall_risk }}
""",
            },
            {
                "name": "Key Recommendations",
                "template": """
Based on the assessment findings, the following actions are recommended:

{{ recommendations }}

These recommendations should be prioritized based on risk level and business impact.
""",
            },
        ],
    },
    "technical_findings": {
        "title": "Technical Findings",
        "description": "Detailed technical analysis and findings",
        "defaults": {
            "finding_count": 0,
            "test_environment": "Production-like environment",
            "tools_used": "Various security testing tools",
        },
        "fields": ["finding_count", "test_environment", "tools_used"],
        "sections": [
            {
                "name": "Test Environment",
                "template": """
Testing Environment: {{ test_environment }}
Tools Used: {{ tools_used }}
Total Findings: {{ finding_count }}
""",
            },
            {
                "name": "Detailed Analysis",
                "template": """
This section contains a detailed technical analysis of all identified issues,
including vulnerability descriptions, impact assessment, and remediation guidance.

Each finding includes:
- Description
- Risk Level
- Affected Components
- Proof of Concept
- Remediation Steps
""",
            },
        ],
    },
    "remediation_roadmap": {
        "title": "Remediation Roadmap",
        "description": "Action plan for remediation and fix timeline",
        "defaults": {
            "phase_1_weeks": 2,
            "phase_2_weeks": 4,
            "phase_3_weeks": 6,
            "critical_actions": "Address all critical findings",
        },
        "fields": [
            "phase_1_weeks",
            "phase_2_weeks",
            "phase_3_weeks",
            "critical_actions",
        ],
        "sections": [
            {
                "name": "Remediation Timeline",
                "template": """
Phase 1 (0-{{ phase_1_weeks }} weeks): Critical Issues
- {{ critical_actions }}
- Immediate security patches
- Emergency vulnerability fixes

Phase 2 ({{ phase_1_weeks }}-{{ phase_2_weeks }} weeks): High Priority Issues
- Address high-severity findings
- Implement security improvements
- Update security controls

Phase 3 ({{ phase_2_weeks }}-{{ phase_3_weeks }} weeks): Medium Priority Issues
- Medium-severity vulnerability fixes
- Process improvements
- Security hardening
""",
            },
            {
                "name": "Success Criteria",
                "template": """
Remediation will be considered complete when:
1. All critical vulnerabilities are patched
2. High-priority findings have mitigation implemented
3. Security controls are validated
4. Follow-up assessment confirms resolution
""",
            },
        ],
    },
}
