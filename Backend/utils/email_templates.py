# Backend/utils/email_templates.py

import datetime

def _base_template(title: str, body_html: str) -> str:
    """Wraps body content in the standardized KavachNet branding wrapper."""
    return f"""
    <!DOCTYPE html>
    <html>
      <body style="font-family: 'Segoe UI', Arial, sans-serif; color: #1e293b; line-height: 1.6; background-color: #f1f5f9; padding: 20px;">
        <div style="max-width: 600px; margin: 0 auto; background-color: #ffffff; border-radius: 8px; overflow: hidden; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);">
          
          <!-- Header -->
          <div style="background-color: #0f172a; padding: 20px; text-align: center;">
            <h1 style="color: #38bdf8; margin: 0; font-size: 24px; letter-spacing: 1px;">KAVACH NET</h1>
            <p style="color: #94a3b8; margin: 5px 0 0 0; font-size: 14px; text-transform: uppercase;">{title}</p>
          </div>
          
          <!-- Body -->
          <div style="padding: 30px;">
            {body_html}
          </div>
          
          <!-- Footer -->
          <div style="background-color: #f8fafc; border-top: 1px solid #e2e8f0; padding: 20px; text-align: center; color: #64748b; font-size: 12px;">
            <p style="margin: 0;">This is an automated notification from the KavachNet Security System.</p>
            <p style="margin: 5px 0 0 0;">Strictly Confidential | Do not forward to unauthorized entities.</p>
          </div>
          
        </div>
      </body>
    </html>
    """

def build_otp_email(otp: str):
    subject = "KavachNet — Your OTP Code"
    
    text_content = f"Your One-Time Password (OTP) for KavachNet login is: {otp}\nValid for 5 minutes. Do NOT share."
    
    html_body = f"""
        <p>Hello,</p>
        <p>Your One-Time Password (OTP) to access the KavachNet dashboard is:</p>
        
        <div style="background-color: #f8fafc; border: 2px dashed #cbd5e1; padding: 15px; text-align: center; margin: 25px 0; border-radius: 6px;">
            <span style="font-family: monospace; font-size: 32px; font-weight: bold; color: #0f172a; letter-spacing: 4px;">{otp}</span>
        </div>
        
        <p style="color: #ef4444; font-weight: bold;">⚠️ Security Notice:</p>
        <p style="margin-top: 5px;">This OTP is valid for exactly 5 minutes. Do <strong>NOT</strong> share this code with anyone, including KavachNet administrators.</p>
    """
    
    return subject, _base_template("Authentication Sequence", html_body), text_content

def build_institution_approval_email(admin_name: str, code: str, expiry: str):
    subject = "KavachNet — Institution Approved!"
    expiry_date = datetime.datetime.fromisoformat(expiry).strftime('%d %b %Y, %I:%M %p')
    
    text_content = f"Hello {admin_name},\nYour institution is approved. Code: {code}\nExpires: {expiry_date}."
    
    html_body = f"""
        <p>Hello {admin_name},</p>
        <p>Great news! Your institution has been formally approved and boarded onto the KavachNet platform.</p>
        
        <div style="background-color: #f0fdf4; border-left: 4px solid #22c55e; padding: 20px; margin: 25px 0;">
            <p style="margin: 0; color: #166534; font-weight: bold; text-transform: uppercase; font-size: 12px;">Active Invitation Code</p>
            <p style="margin: 5px 0 0 0; font-family: monospace; font-size: 24px; color: #14532d;">{code}</p>
        </div>
        
        <p>You can use this code to register your initial Administrator account on the portal.</p>
        <p><strong>Security Policy:</strong> This code rotates and will automatically expire on <strong>{expiry_date}</strong>. Subsequent codes will be assigned directly via your SOC dashboard or delivered via targeted security briefings.</p>
        
        <p>Welcome to the shield.</p>
    """
    
    return subject, _base_template("Boarding Complete", html_body), text_content

def build_code_update_email(admin_name: str, inst_name: str, old_code: str, new_code: str, expiry: str):
    subject = "[Kavach Net] New Access Code Assigned for Your Institution"
    expiry_date = datetime.datetime.fromisoformat(expiry).strftime('%d %b %Y, %I:%M %p')
    
    masked_old = f"****{old_code[-4:]}" if old_code and len(old_code) >= 4 else "N/A"
    
    text_content = f"Institution: {inst_name}. Old Code: {masked_old} expired. New Code: {new_code}. Expires: {expiry_date}."
    
    html_body = f"""
        <p>Hello <strong>{admin_name}</strong>,</p>
        <p>This is an automated operational notification. A new access code sequence has been generated and securely assigned to your institution (<strong>{inst_name}</strong>).</p>
        
        <table width="100%" style="border-collapse: collapse; margin: 25px 0;">
            <tr>
                <td style="padding: 15px; border: 1px solid #e2e8f0; background-color: #f8fafc; color: #64748b; width: 40%;">
                    Previous Code (Revoked)
                </td>
                <td style="padding: 15px; border: 1px solid #e2e8f0; font-family: monospace; font-weight: bold; color: #94a3b8; text-decoration: line-through;">
                    {masked_old}
                </td>
            </tr>
            <tr>
                <td style="padding: 15px; border: 1px solid #e2e8f0; background-color: #eff6ff; color: #1e3a8a; font-weight: bold;">
                    New Active Code
                </td>
                <td style="padding: 15px; border: 1px solid #e2e8f0; background-color: #dbeafe; font-family: monospace; font-size: 18px; font-weight: bold; color: #1e40af;">
                    {new_code}
                </td>
            </tr>
            <tr>
                <td style="padding: 15px; border: 1px solid #e2e8f0; background-color: #f8fafc; color: #64748b;">
                    Validity Window
                </td>
                <td style="padding: 15px; border: 1px solid #e2e8f0; color: #334155;">
                    Valid until {expiry_date}
                </td>
            </tr>
        </table>
        
        <p><strong>Protocol Reminder:</strong> This rotation was executed per core security protocols or forcefully initiated by a Super Administrator. The previous sequence is now defunct and will fail backend authentications.</p>
        
        <p style="color: #ef4444; font-weight: bold;">⚠️ Critical Directive:</p>
        <p style="margin-top: 5px;">Restrict visibility of this sequence. Only provision to highly vetted personnel. Treat this code as sensitive material.</p>
    """
    
    return subject, _base_template("Access Rotation", html_body), text_content

def build_threat_alert_email(inst_name: str, threat_details: str, severity: str):
    subject = f"KavachNet — Threat Alert [{severity}]"
    
    text_content = f"Institution: {inst_name}. Severity: {severity}. Details: {threat_details}."
    
    color = "#ef4444" if severity.upper() in ["HIGH", "CRITICAL_ATTACK"] else "#f59e0b"
    
    html_body = f"""
        <h2 style="color: {color};">Security Anomaly Detected</h2>
        <p>This is an automated threat intelligence alert concerning your institution context (<strong>{inst_name}</strong>).</p>
        
        <div style="background-color: #fff1f2; border-left: 4px solid {color}; padding: 15px; margin: 20px 0;">
            <p style="margin: 0; font-weight: bold; color: {color};">Severity: {severity}</p>
            <p style="margin: 5px 0 0 0; font-family: monospace; font-size: 14px; background: #ffe4e6; padding: 10px; border-radius: 4px;">{threat_details}</p>
        </div>
        
        <p>Please review your SOC dashboard immediately to implement mitigation protocols.</p>
    """
    
    return subject, _base_template("Threat Intelligence", html_body), text_content

def build_incident_email(inst_name: str, incident_type: str, message: str, severity: str):
    subject = f"KavachNet — Incident Report: {incident_type}"
    
    text_content = f"Institution: {inst_name}. Type: {incident_type}. Severity: {severity}. Message: {message}."
    
    html_body = f"""
        <h2>Incident Escalation</h2>
        <p>A formalized incident has been logged against your institutional security perimeter (<strong>{inst_name}</strong>).</p>
        
        <table width="100%" style="border-collapse: collapse; margin: 25px 0;">
            <tr>
                <td style="padding: 10px; border-bottom: 1px solid #e2e8f0; font-weight: bold; color: #64748b; width: 30%;">Incident Type</td>
                <td style="padding: 10px; border-bottom: 1px solid #e2e8f0; color: #0f172a;">{incident_type}</td>
            </tr>
            <tr>
                <td style="padding: 10px; border-bottom: 1px solid #e2e8f0; font-weight: bold; color: #64748b;">Severity</td>
                <td style="padding: 10px; border-bottom: 1px solid #e2e8f0; font-weight: bold;">{severity}</td>
            </tr>
            <tr>
                <td style="padding: 10px; border-bottom: 1px solid #e2e8f0; font-weight: bold; color: #64748b;">Actionable Details</td>
                <td style="padding: 10px; border-bottom: 1px solid #e2e8f0; font-family: monospace; background-color: #f8fafc;">{message}</td>
            </tr>
        </table>
        
        <p>Please refer to the incident management console to assign responders or close this ticket.</p>
    """
    
    return subject, _base_template("Incident Reporting", html_body), text_content

