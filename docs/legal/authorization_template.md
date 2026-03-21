# Penetration Testing Authorization Template

> **IMPORTANT:** This is a template only. Have this document reviewed and signed
> by your legal team and the client before conducting any security testing.
> Never conduct SQL injection testing without explicit written authorization.

---

## PENETRATION TESTING AUTHORIZATION AGREEMENT

**Date:** _______________

**Client Organization:** _______________________________________________

**Client Representative (Authorized Signatory):**
- Name: _______________________________________________
- Title: _______________________________________________
- Email: _______________________________________________
- Phone: _______________________________________________

**Testing Organization:** _______________________________________________

**Lead Tester:**
- Name: _______________________________________________
- Certification(s): _______________________________________________

---

## 1. SCOPE OF AUTHORIZED TESTING

### 1.1 Target Systems

The following systems are authorized for penetration testing:

| System/URL | IP Address | Description |
|-----------|------------|-------------|
| | | |
| | | |
| | | |

### 1.2 Authorized Test Types

- [ ] SQL Injection testing
- [ ] Authentication bypass testing
- [ ] File system access testing
- [ ] Operating system command execution testing
- [ ] Network lateral movement testing (if applicable)
- [ ] Social engineering (if applicable)
- [ ] Other: _______________________________________________

### 1.3 Out of Scope

The following systems/activities are explicitly **NOT** authorized:
- _______________________________________________
- _______________________________________________

---

## 2. TESTING WINDOW

| Parameter | Details |
|-----------|---------|
| Start Date | |
| End Date | |
| Authorized Hours | |
| Time Zone | |
| Emergency Contact | |

---

## 3. RULES OF ENGAGEMENT

### 3.1 Permitted Activities
- Enumerate database structure and metadata
- Extract limited data as proof of concept (minimum necessary)
- Test authentication mechanisms
- Attempt privilege escalation within authorized scope

### 3.2 Prohibited Activities
- Exfiltrating large volumes of production data
- Modifying, deleting, or corrupting production data
- Denial of Service attacks
- Testing systems outside the defined scope
- Sharing findings with unauthorized parties
- Leaving backdoors or unauthorized access after testing

### 3.3 Data Handling
- All extracted data must be stored securely and encrypted
- Data must be deleted within ___ days of report delivery
- No production PII/sensitive data to be included in reports (redact as needed)
- Findings shared only with named recipients below

---

## 4. EMERGENCY PROCEDURES

If testing causes unintended impact:

1. **Immediately stop** all testing activities
2. **Contact** client emergency contact: _______________________________________________
3. **Document** what actions were taken and when
4. **Preserve** all logs and artifacts
5. **Do not attempt to "fix"** the issue without explicit instruction

---

## 5. LIABILITY AND LEGAL

The client authorizes the testing organization and named testers to perform the activities described above. This authorization is limited to the scope defined in Section 1.

The client acknowledges:
- Testing may temporarily impact system performance
- Testing activities may trigger security alerts
- The testing organization is not liable for pre-existing vulnerabilities

---

## 6. NAMED RECIPIENTS FOR FINDINGS

Penetration test findings will be shared **only** with:

| Name | Role | Email |
|------|------|-------|
| | | |
| | | |

---

## 7. SIGNATURES

**Client Authorization:**

Signature: _____________________________ Date: _______________

Name (Print): _________________________

Title: ________________________________


**Testing Organization:**

Signature: _____________________________ Date: _______________

Name (Print): _________________________

Title: ________________________________

---

## CHECKLIST (Complete before testing)

- [ ] This document is fully signed by both parties
- [ ] All target systems confirmed in writing
- [ ] Emergency contacts verified and reachable
- [ ] Testing window confirmed
- [ ] Evidence collection method ready
- [ ] Secure storage for extracted data prepared
- [ ] Report template ready
- [ ] All testers briefed on scope and rules

**DO NOT BEGIN TESTING UNTIL ALL BOXES ARE CHECKED**
