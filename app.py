import os
import re
import logging
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, jsonify

app = Flask(__name__)
app.secret_key = 'sec_audit_checklist_sentinel_key_2026'

# ====== 1. SECURE AUDIT LOGGING SETUP ======
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(BASE_DIR, 'audit_checklist.log')

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)

# Demo Auditor Credentials (Authentication Concept)
AUDITORS = {
    'auditor_secops': 'Shield@Auditor2026',
    'lead_analyst': 'CyberAudit#9988'
}

# Standard Security Controls Definition (CIS / NIST aligned)
SECURITY_CONTROLS = [
    {
        'id': 'ctrl_mfa',
        'title': 'Identity & Access: Multi-Factor Authentication (MFA)',
        'desc': 'Enforce hardware token or TOTP MFA across all administrative and SSH/RDP endpoints.',
        'weight': 20,
        'remediation': 'Deploy WebAuthn/FIDO2 MFA; immediately revoke password-only admin privileges.'
    },
    {
        'id': 'ctrl_encryption',
        'title': 'Data Protection: AES-256 Storage Encryption',
        'desc': 'All customer records, database clusters, and cloud storage volumes must be encrypted at rest.',
        'weight': 15,
        'remediation': 'Enable automated Key Management Service (KMS) envelope encryption for production databases.'
    },
    {
        'id': 'ctrl_tls',
        'title': 'Network Transport: TLS 1.3 & HSTS Enforcement',
        'desc': 'Deprecate TLS 1.0/1.1; enforce TLS 1.3 with strong cipher suites and 1-year HSTS preload headers.',
        'weight': 15,
        'remediation': 'Update web server SSL/TLS config; disable weak renegotiation and enable forward secrecy.'
    },
    {
        'id': 'ctrl_patch',
        'title': 'Vulnerability & Patch Lifecycle Management',
        'desc': 'Critical CVEs remediated within a strict 14-day window with active monthly vulnerability scans.',
        'weight': 20,
        'remediation': 'Implement automated CI/CD container scanning and automated OS security patch pipelines.'
    },
    {
        'id': 'ctrl_logging',
        'title': 'Defensive SIEM & Tamper-Proof Audit Logging',
        'desc': 'Centralized immutable logging (Syslog/SIEM) capturing authentication and privilege escalation events.',
        'weight': 15,
        'remediation': 'Route audit events to a dedicated WORM (Write Once Read Many) log storage server.'
    },
    {
        'id': 'ctrl_backup',
        'title': 'Business Continuity: Air-Gapped Immutable Backups',
        'desc': 'Offline or write-locked immutable daily backups with tested disaster recovery drills.',
        'weight': 15,
        'remediation': 'Establish 3-2-1 backup topology with air-gapped immutable storage to neutralize ransomware.'
    }
]

@app.route('/')
def home():
    if 'auditor' in session:
        return redirect(url_for('audit_console'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        # Authentication Check
        if username in AUDITORS and AUDITORS[username] == password:
            session['auditor'] = username
            logging.info(f"AUDITOR_LOGIN: Authorized session created for [{username}] | IP: {request.remote_addr}")
            return redirect(url_for('audit_console'))
        else:
            logging.warning(f"UNAUTHORIZED_ACCESS_ATTEMPT: Failed login for [{username}] | IP: {request.remote_addr}")
            error = "Invalid Auditor credentials or revoked clearance."

    return render_template('login.html', error=error)

@app.route('/audit')
def audit_console():
    if 'auditor' not in session:
        return redirect(url_for('login'))
    return render_template('audit.html', auditor=session['auditor'], controls=SECURITY_CONTROLS)

@app.route('/submit-audit', methods=['POST'])
def submit_audit():
    if 'auditor' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.get_json() or {}
    target = data.get('target', '').strip()
    scope = data.get('scope', '').strip()
    answers = data.get('answers', {})

    # Input Validation
    if not target or not re.match(r'^[a-zA-Z0-9.\-_:/]{3,60}$', target):
        return jsonify({'error': 'Invalid target domain, IP, or hostname specification.'}), 400

    # Calculate Compliance Score and Risk Level
    total_score = 0
    passed_controls = []
    failed_controls = []

    for ctrl in SECURITY_CONTROLS:
        c_id = ctrl['id']
        is_passed = bool(answers.get(c_id, False))
        if is_passed:
            total_score += ctrl['weight']
            passed_controls.append(ctrl['title'])
        else:
            failed_controls.append({
                'title': ctrl['title'],
                'remediation': ctrl['remediation']
            })

    # Risk Classification
    if total_score >= 85:
        risk_level = "LOW RISK (Compliant)"
        risk_color = "#10b981"
    elif total_score >= 60:
        risk_level = "MODERATE RISK (Action Required)"
        risk_color = "#f59e0b"
    elif total_score >= 40:
        risk_level = "HIGH RISK (Vulnerable)"
        risk_color = "#f97316"
    else:
        risk_level = "CRITICAL RISK (Compromise Imminent)"
        risk_color = "#ef4444"

    # Audit Trail Logging
    logging.info(
        f"AUDIT_EVALUATION_COMPLETED: Auditor: [{session['auditor']}] | "
        f"Target: [{target}] | Scope: [{scope}] | Score: {total_score}% | "
        f"Risk: [{risk_level}] | Passed: {len(passed_controls)} | Failed: {len(failed_controls)}"
    )

    return jsonify({
        'score': total_score,
        'risk_level': risk_level,
        'risk_color': risk_color,
        'passed_count': len(passed_controls),
        'failed_count': len(failed_controls),
        'remediations': failed_controls,
        'timestamp': datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    })

@app.route('/logout')
def logout():
    auditor = session.pop('auditor', None)
    if auditor:
        logging.info(f"AUDITOR_LOGOUT: Session terminated for [{auditor}]")
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True, port=5000)