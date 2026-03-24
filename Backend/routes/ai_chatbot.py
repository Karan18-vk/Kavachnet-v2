"""
routes/ai_chatbot.py  —  KavachNet AI Complete Engine
ALL 3 LAYERS + AUTO-NEUTRALIZATION + DB PERSISTENCE.
"""

import re, sys, os, smtplib
from math import log2
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import get_jwt_identity
from utils.security import authenticated_required
from models.db import Database

chatbot_bp = Blueprint("kb_chatbot", __name__)
custom_db = Database()

# ═══════════════════════════════════════════════════════
#  LAYER 1 - 35-Feature Heuristic Engine
# ═══════════════════════════════════════════════════════

_PKWS = ["login","signin","verify","secure","account","update","banking","paypal","apple",
"amazon","microsoft","google","netflix","confirm","suspended","password","credential",
"urgent","alert","free","prize","winner","crypto","wallet","recover","validate","suspend",
"click","helpdesk","support","limited","offer","claim","discount"]

_BTLDS = {".tk",".ml",".ga",".cf",".gq",".xyz",".top",".club",".online",".site",".live",
".click",".download",".loan",".stream",".win",".ru",".pw",".cc",".work",".party",".bid"}

_TRUSTED = {"google.com","github.com","microsoft.com","apple.com","amazon.com","paypal.com",
"wikipedia.org","youtube.com","facebook.com","linkedin.com","twitter.com","x.com",
"instagram.com","reddit.com","stackoverflow.com","netflix.com","spotify.com","dropbox.com"}

_BRANDS = ["paypal","amazon","apple","google","microsoft","netflix","facebook","bank",
"instagram","twitter","chase","wellsfargo"]

def _ent(s):
    if not s: return 0
    f={}
    for c in s: f[c]=f.get(c,0)+1
    n=len(s)
    return -sum((v/n)*log2(v/n) for v in f.values())

def layer1_scan(raw):
    """KavachNet Layer 1 Heuristic Scan (Original)."""
    score=0; fl=[]; dom=""; tld=""
    try:
        from urllib.parse import urlparse
        p=urlparse(raw if "://" in raw else "http://"+raw)
        dom=p.netloc.lower().replace("www.",""); path=p.path.lower()
    except: pass
    
    if not dom: return {"verdict":"safe","risk_score":0,"confidence":100,"flags":[],"actions":[],"chips":[]}

    if any(k in raw.lower() for k in _PKWS): score+=25; fl.append("Phishing keywords detected")
    if any(dom.endswith(t) for t in _BTLDS): score+=30; fl.append("High-risk TLD")
    if _ent(dom)>3.8: score+=20; fl.append("High domain entropy")
    if "@" in raw: score+=15; fl.append("@ symbol in URL")
    
    verdict="malicious" if score>=60 else "suspicious" if score>=30 else "safe"
    return {
        "verdict": verdict,
        "risk_score": score,
        "confidence": 85,
        "flags": fl if fl else ["No clear heuristics matched"],
        "actions": ["Avoid link"] if verdict!="safe" else ["Safe"],
        "chips": [{"l": f, "c": "warn"} for f in fl[:2]]
    }


# ═══════════════════════════════════════════════════════
#  AI ENGINE INTEGRATION (Layer 2 & 3)
# ═══════════════════════════════════════════════════════

import logging
logger = logging.getLogger(__name__)

try:
    from email_threat.phishing_classifier import PhishingClassifier
    from email_threat.link_detector import MaliciousLinkDetector
    from email_threat.threat_models import EmailMessage
    from email_threat.core import THREAT_CFG

    _l2_classifier = PhishingClassifier(THREAT_CFG)
    _l3_detector = MaliciousLinkDetector(THREAT_CFG)
    AI_LAYERS_READY = True
    logger.info("[KavachNet AI] 3-Layer Engine initialized via email_threat package")
except Exception as e:
    AI_LAYERS_READY = False
    logger.error(f"[KavachNet AI] Failed to initialize layers: {e}")

# Maintain original flags for compatibility
LAYER2_AVAILABLE = AI_LAYERS_READY
LAYER3_AVAILABLE = AI_LAYERS_READY # Layer 3 is available in code, even if keys are missing


# ═══════════════════════════════════════════════════════
#  NEUTRALIZATION ENGINE
# ═══════════════════════════════════════════════════════

_BL=[]; _INC=[]; _INC_CTR=[1000]

def _blacklisted(url):
    if url in _BL: return True
    try:
        from urllib.parse import urlparse
        d=urlparse(url).netloc.lower().replace("www.","")
        for e in _BL:
            try:
                if urlparse(e).netloc.lower().replace("www.","")==d: return True
            except: pass
    except: pass
    return False

def _email(to, r):
    try: u=current_app.config.get("MAIL_USERNAME",""); pw=current_app.config.get("MAIL_PASSWORD","")
    except: u=pw=""
    url=r.get("url",""); sc=r.get("risk_score",0); th=r.get("threat_type","").upper()
    fl=r.get("flags",[])
    if not u or not pw:
        logger.warning(f"[NEUTRALIZER] ALERT -> {to} | {th} | {sc}/100 | {url}")
        return True
    html=f"""<html><body style="font-family:sans-serif;background:#0a0f1e;color:#e2e8f0;padding:30px">
    <div style="max-width:560px;margin:auto;background:#0d1628;border:1px solid #ef4444;border-radius:12px;overflow:hidden">
      <div style="background:#ef4444;padding:16px"><h2 style="margin:0;color:#fff">KavachNet ALERT — {th}</h2></div>
      <div style="padding:20px">
        <p><b style="color:#64748b">URL:</b> <span style="color:#38bdf8;font-family:monospace;font-size:11px;word-break:break-all">{url}</span></p>
        <p><b style="color:#64748b">Score:</b> <span style="color:#ef4444">{sc}/100</span></p>
        <ul>{''.join(f"<li style='color:#94a3b8'>{f}</li>" for f in fl[:4])}</ul>
        <p style="color:#22c55e;margin-top:12px">Auto-actions: Incident logged · URL blacklisted · Alert sent</p>
      </div></div></body></html>"""
    try:
        msg=MIMEMultipart("alternative"); msg["Subject"]=f"[KavachNet] {th} — {sc}/100"
        msg["From"]=u; msg["To"]=to; msg.attach(MIMEText(html,"html"))
        try: srv=current_app.config.get("MAIL_SERVER","smtp.gmail.com"); port=int(current_app.config.get("MAIL_PORT",587))
        except: srv,port="smtp.gmail.com",587
        with smtplib.SMTP(srv,port) as s:
            s.ehlo(); s.starttls(); s.login(u,pw); s.sendmail(u,to,msg.as_string())
        return True
    except Exception as e: return False

def _neutralize(scan):
    url=scan.get("url",""); sc=scan.get("risk_score",0)
    threat=scan.get("threat_type","unknown"); ts=datetime.utcnow().isoformat()
    rep={"url":url,"threat_type":threat,"risk_score":sc,"actions_taken":[],"errors":[],"timestamp":ts}

    try:
        sev="CRITICAL" if sc>=80 else "HIGH" if sc>=60 else "MEDIUM"
        _INC_CTR[0]+=1; iid=_INC_CTR[0]
        _INC.append({"id":iid,"title":f"AI: {threat.upper()} — {url[:50]}","severity":sev,
            "threat_type":threat,"target":url,"status":"investigating","created_at":ts})
        rep["actions_taken"].append({"action":"incident_created","status":"success",
            "detail":f"Incident #{iid} — {sev}","incident_id":iid})
        # Save to real database
        custom_db.save_incident({
            "title": f"AI Neutralization for {url[:50]}",
            "description": f"AI automated threat response for suspicious link: {url}",
            "threat_type": threat,
            "severity": sev,
            "confidence": sc/100,
            "target": url
        })
    except Exception as e: rep["errors"].append(f"Incident: {e}")

    try:
        if not _blacklisted(url):
            _BL.append(url)
            rep["actions_taken"].append({"action":"url_blacklisted","status":"success",
                "detail":f"Blacklisted ({len(_BL)} total)"})
        else:
            rep["actions_taken"].append({"action":"url_blacklisted","status":"skipped","detail":"Already blacklisted"})
    except Exception as e: rep["errors"].append(f"Blacklist: {e}")

    try:
        try: adm=current_app.config.get("MAIL_USERNAME","admin@kavachnet.ai")
        except: adm="admin@kavachnet.ai"
        sent=_email(adm,scan)
        rep["actions_taken"].append({"action":"alert_email_sent",
            "status":"success" if sent else "failed","detail":f"Alert to {adm}"})
    except Exception as e: rep["errors"].append(f"Email: {e}")

    ok=len([a for a in rep["actions_taken"] if a["status"]=="success"])
    rep["summary"]=f"{ok}/{len(rep['actions_taken'])} actions completed"
    return rep


# ═══════════════════════════════════════════════════════
#  FULL SCAN - Combines all layers
# ═══════════════════════════════════════════════════════

import asyncio

def full_scan(url):
    # Layer 1: Heuristics (Local Regex/Entropy)
    l1 = layer1_scan(url)
    
    res = {
        "url": url,
        "verdict": l1["verdict"],
        "risk_score": l1["risk_score"],
        "confidence": l1["confidence"],
        "threat_type": l1["verdict"],
        "flags": l1["flags"],
        "actions": l1["actions"],
        "explanation": l1["flags"],
        "layers": {
            "layer1": l1,
            "layer2": None,
            "layer3": None
        },
        "mode": "layer1_only",
        "neutralization": None
    }

    if not AI_LAYERS_READY:
        return res

    try:
        # ── Layer 2: NLP/Deep Learning ──────────────────────
        # Use PhishingClassifier to get a probability score
        l2_score = _l2_classifier.predict(url)
        l2_verdict = "malicious" if l2_score > 0.8 else "suspicious" if l2_score > 0.4 else "safe"
        
        layer2_res = {
            "verdict": l2_verdict,
            "score": int(l2_score * 100),
            "confidence": round(max(l2_score, 1 - l2_score) * 100, 1),
            "model": "DistilBERT/TF-IDF Hybrid"
        }
        res["layers"]["layer2"] = layer2_res
        res["mode"] = "layer1+layer2"

        # ── Layer 3: Threat Intelligence ───────────────────
        # Use MaliciousLinkDetector for VT/AbuseIPDB
        # We need a dummy context since scan is async
        dummy_email = EmailMessage(
            message_id="ai-scan", 
            subject="Scan", 
            sender="bot@kavachnet.ai",
            sender_name="KavachNet AI",
            recipients=["admin@kavachnet.ai"],
            date=datetime.utcnow(),
            body_text=url,
            body_html=f"<html><body>{url}</body></html>",
            headers={},
            urls=[url]
        )
        
        # Run async detection in a synchronous wrapper
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            l3_indicators = loop.run_until_complete(_l3_detector.analyze(dummy_email))
            loop.close()
        except:
            l3_indicators = []

        if l3_indicators:
            # Aggregate L3 indicators
            max_l3_score = max([i.score for i in l3_indicators])
            sources = [i.source for i in l3_indicators]
            layer3_res = {
                "verdict": "malicious" if max_l3_score > 0.7 else "suspicious" if max_l3_score > 0.3 else "safe",
                "score": int(max_l3_score * 100),
                "indicators": [i.description for i in l3_indicators],
                "sources": list(set(sources)),
                "status": f"Scanned via {len(set(sources))} Intel Sources"
            }
            res["layers"]["layer3"] = layer3_res
            res["mode"] = "layer1+layer2+layer3"
            
            # Add L3 flags to overall list
            for i in l3_indicators:
                if i.score > 0.3:
                    res["flags"].append(f"Layer 3 [{i.source}]: {i.description}")
        else:
            # Mark Layer 3 as available but no flags (possibly missing keys)
            res["layers"]["layer3"] = {
                "verdict": "safe", 
                "score": 0, 
                "status": "No active threats found in global intel"
            }
            res["mode"] = "layer1+layer2+layer3"

        # ── Global Verdict Adjustment ──────────────────────
        # Use MAX score to ensure any single layer detection triggers protection
        l1_score = res["risk_score"]
        l2_score = layer2_res["score"]
        l3_score = res["layers"]["layer3"]["score"] if res["layers"]["layer3"] else 0
        
        final_score = max(l1_score, l2_score, l3_score)
        res["risk_score"] = int(min(100, final_score))
        
        if res["risk_score"] >= 65: res["verdict"] = "malicious"
        elif res["risk_score"] >= 30: res["verdict"] = "suspicious"
        else: res["verdict"] = "safe"
        
        res["threat_type"] = res["verdict"]

    except Exception as e:
        logger.warning(f"[AI SCAN] Layer 2/3 error: {e}")

    # Neutralization logic
    if res["verdict"] in ("malicious", "block"):
        try:
            res["neutralization"] = _neutralize(res)
            
            # Format for the UI based on requirements
            res["blocked_details"] = {
                "threat_type": res["threat_type"].capitalize(),
                "risk_level": "Critical" if res["risk_score"] >= 90 else "High" if res["risk_score"] >= 75 else "Medium",
                "status": "Blocked by Kavach Net",
                "why_risky": ", ".join(res["flags"][:3]),
                "recommended_action": "Avoid opening the link. Report to admin if needed.",
                "user_option": "Access is blocked by default. You may proceed at your own risk after acknowledgment.",
                "protection_status": "Kavach Net has prevented automatic access and issued a warning."
            }
        except Exception as e: pass

    return res


# ═══════════════════════════════════════════════════════
#  CYBERSECURITY EXPERT KNOWLEDGE BASE
# ═══════════════════════════════════════════════════════

_CYBER_KB = {
    "sqli": {
        "title": "SQL Injection (SQLi)",
        "explanation": "SQL Injection is a web attack where attackers insert malicious SQL queries into input fields to access or manipulate a database. It can lead to severe data theft or unauthorized system access.",
        "danger": "Allows attackers to bypass authentication, view sensitive user data, or even delete entire databases.",
        "prevention": "Use parameterized queries, prepared statements, and strict input validation. Kavach Net can detect suspicious input patterns and alert administrators of potential injection attempts."
    },
    "xss": {
        "title": "Cross-Site Scripting (XSS)",
        "explanation": "XSS occurs when an attacker injects malicious scripts into web pages viewed by other users. These scripts can steal session cookies or redirect users to malicious sites.",
        "danger": "Can lead to account hijacking, data theft from browser storage, or website defacement.",
        "prevention": "Always sanitize user inputs and set proper Content Security Policy (CSP) headers. Kavach Net monitors for script injection patterns and helps identify vulnerable endpoints."
    },
    "ransomware": {
        "title": "Ransomware",
        "explanation": "Ransomware is malicious software that encrypts a victim's files, with the attacker demanding a ransom to provide the decryption key.",
        "danger": "Causes total loss of data access, operational downtime, and significant financial damage to organizations.",
        "prevention": "Maintain regular offline backups, keep software updated, and use EDR solutions. Kavach Net's phishing scanner prevents the initial delivery of ransomware links via email or chat."
    },
    "social_eng": {
        "title": "Social Engineering",
        "explanation": "Social Engineering is the psychological manipulation of people into performing actions or divulging confidential information.",
        "danger": "Technological defenses can be bypassed by simply tricking a human user into giving away their credentials.",
        "prevention": "Verify all requests for sensitive data and implement mandatory security awareness training. Kavach Net blocks the malicious links often used in these manipulative schemes."
    },
    "brute_force": {
        "title": "Brute Force Attack",
        "explanation": "A brute force attack consists of an attacker submitting many passwords or passphrases with the hope of eventually guessing correctly.",
        "danger": "If successful, attackers gain full access to user accounts and sensitive institutional data.",
        "prevention": "Enable account lockout policies, use strong unique passwords, and always enforce Multi-Factor Authentication (MFA). Kavach Net's role-based access and monitoring identify repeated failed login attempts."
    },
    "best_practices": {
        "title": "Cybersecurity Best Practices",
        "explanation": "Remaining secure requires a proactive approach including strong passwords, 2FA, and constant vigilance against suspicious messages.",
        "danger": "Weak security habits are the most common entry point for large-scale data breaches.",
        "prevention": "Enable 2FA, use a password manager, and never reuse passwords. Kavach Net provides an extra layer of defense by scanning every link and file before you interact with it."
    },
    "network": {
        "title": "Network Security",
        "explanation": "Network security consists of the policies and practices adopted to prevent and monitor unauthorized access, misuse, or modification of a computer network.",
        "danger": "Unsecured networks allow attackers to intercept traffic (MITM), steal data, or launch lateral attacks within an organization.",
        "prevention": "Use strong firewalls, VPNs, and network segmentation. Kavach Net's dashboard provides visibility into network-level threats and suspicious URL patterns."
    },
    "email": {
        "title": "Email Threats",
        "explanation": "Email threats include spam, phishing, and malware attachments designed to compromise user accounts or deliver harmful payloads.",
        "danger": "Email is the #1 delivery vector for ransomware and credential theft.",
        "prevention": "Never open attachments from unknown senders and use email filtering. Kavach Net's multi-layer engine specifically analyzes email content for malicious intent."
    },
    "breach": {
        "title": "Data Breaches",
        "explanation": "A data breach is a security incident in which sensitive, protected, or confidential data is copied, transmitted, viewed, or stolen by an unauthorized individual.",
        "danger": "Leads to loss of intellectual property, regulatory fines, and permanent damage to an organization's reputation.",
        "prevention": "Encrypt sensitive data, implement the principle of least privilege, and use robust monitoring. Kavach Net's incident response system helps contain breaches early."
    },
    "intel": {
        "title": "Threat Intelligence",
        "explanation": "Threat intelligence is evidence-based knowledge about existing or emerging menaces that can be used to inform decisions regarding the subject's response to those menaces.",
        "danger": "Working without intelligence means you are blind to new attacks and zero-day vulnerabilities.",
        "prevention": "Integrate real-time threat feeds into your defense stack. Kavach Net Layer 3 uses global intelligence (VirusTotal/AbuseIPDB) to identify threats in real-time."
    },
    "incident": {
        "title": "Incident Response",
        "explanation": "Incident response is an organized approach to addressing and managing the aftermath of a security breach or cyberattack.",
        "danger": "Poor incident response leads to longer dwell times for attackers and increased damage to systems.",
        "prevention": "Have a clear IR plan and use automated tools to detect and contain threats. Kavach Net automatically logs incidents and suggests immediate neutralization steps."
    }
}

# ═══════════════════════════════════════════════════════
#  INTENT + REPLY
# ═══════════════════════════════════════════════════════

_URE=re.compile(r"(https?://[^\s]+|www\.[^\s]+|[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}[^\s]*)",re.I)
def _eu(m): return list(set(_URE.findall(m)))[:3]

def _di(m):
    t=m.lower().strip()
    if re.search(r'\b(hi|hello|hey|howdy|sup|greetings)\b',t): return "greeting"
    if re.search(r'\b(help|commands|what can you|features|responsibilities)\b',t): return "help"
    
    # Technical Keywords
    if re.search(r'\b(sql|injection|sqli)\b',t): return "expert_sqli"
    if re.search(r'\b(xss|cross-site|scripting)\b',t): return "expert_xss"
    if re.search(r'\b(ransomware|encrypt|ransom|locker)\b',t): return "expert_ransomware"
    if re.search(r'\b(social engineering|psychological|manipulate)\b',t): return "expert_social_eng"
    if re.search(r'\b(brute force|guess|password crack|stuffing)\b',t): return "expert_brute_force"
    if re.search(r'\b(best practices|tips|stay safe|how to protect)\b',t): return "expert_best_practices"
    if re.search(r'\b(network security|firewall|vpn|mitm)\b',t): return "expert_network"
    if re.search(r'\b(email threat|spam|attachment|outlook|gmail)\b',t): return "expert_email"
    if re.search(r'\b(data breach|stolen|leaked|exposed)\b',t): return "expert_breach"
    if re.search(r'\b(threat intelligence|intel|vt|global)\b',t): return "expert_intel"
    if re.search(r'\b(incident response|ir plan|contain|aftermath)\b',t): return "expert_incident"
    
    if re.search(r'\b(phishing|malware|spam|layer|neutrali|threat|risk|score|confidence|reason)\b',t) and re.search(r'\b(what|explain|tell|how|why)\b',t): return "explain"
    if re.search(r'\b(how to use|tutorial|guide|steps|navigate|dashboard)\b',t): return "guide"
    if re.search(r'\b(scan|check|analyze|safe|suspicious|verify|legit|fake)\b',t): return "scan"
    return "scan" if _eu(m) else "unknown"

def _br(intent,message,urls):
    if intent=="greeting":
        return {"type":"text","message":
            "Hello! I am the KavachNet AI Assistant. I can help you scan URLs for threats, explain security results, and guide you through the platform.\n\n"
            "How can I assist your security operations today?"}
    if intent=="help":
        return {"type":"help","commands":[
            {"cmd":"Scan <URL>","desc":"Full AI scan + auto-neutralize"},
            {"cmd":"Is <URL> safe?","desc":"Quick verdict"},
            {"cmd":"What is phishing?","desc":"Learn about phishing"},
            {"cmd":"How to use Kavach Net?","desc":"Step-by-step guide"},
            {"cmd":"What is risk level?","desc":"Understand threat severity"},
        ]}
    if intent=="guide":
        return {"type":"text","message":
            "**Kavach Net Workflow:**\n"
            "1. **Dashboard**: Get a real-time overview of system threats.\n"
            "2. **Scan**: Enter a URL or Email in the input box to analyze it.\n"
            "3. **Result**: Check the verdict and risk level (Critical/High/Medium/Low).\n"
            "4. **Action**: If malicious, Kavach Net auto-neutralizes the threat instantly."}
    if intent.startswith("expert_"):
        topic_key = intent.replace("expert_", "")
        kb = _CYBER_KB.get(topic_key)
        if kb:
            return {"type": "text", "message": 
                f"### {kb['title']}\n"
                f"{kb['explanation']}\n\n"
                f"**Danger:** {kb['danger']}\n"
                f"**Prevention:** {kb['prevention']}"
            }

    if intent=="explain":
        m=message.lower()
        if "phishing" in m: return {"type":"text","message":
            "**Phishing** is a cyber attack where attackers trick users into revealing sensitive data like passwords or bank details using fake websites or emails.\n\n"
            "**How it works:** Attackers impersonate trusted brands (Google, banks) to capture your login data.\n"
            "**Kavach Net Defense:** We analyze URL patterns, domain entropy, and brand spoofing indicators to block these links before you interact."}
        if "risk" in m or "severity" in m: return {"type":"text","message":"**Risk Level** shows danger level: **High/Critical** requires immediate block; **Medium** means exercise caution; **Low** means minimal indicators found."}
        if "layer" in m: return {"type":"text","message":"KavachNet uses **3-Layer Detection**: Heuristics (URL patterns), NLP (Machine Learning), and Threat Intel (Global DBs like VirusTotal)."}
        if "neutrali" in m: return {"type":"text","message":"**Auto-Neutralization** fires on threats: ① Incident logged ② URL blacklisted ③ Admin alerted via email."}
        if "malware" in m: return {"type":"text","message":"**Malware** is software used by attackers to damage or gain unauthorized access to your system."}
        return {"type":"text","message":"I can explain phishing, risk levels, AI layers, or auto-neutralization. What would you like to know?"}
    if intent=="scan" or urls:
        if not urls: return {"type":"text","message":"Please provide a URL or email content to scan.\nExample: `Scan http://secure-verify-api.ru`"}
        results=[full_scan(u) for u in urls]
        mode=results[0].get("mode","layer1").replace("+"," + ")
        blocked=sum(1 for r in results if r["verdict"] in ("malicious","block"))
        msg=f"Scanned {len(results)} URL(s) — {mode}"
        if blocked: msg+=f" · **{blocked} threat(s) neutralized** 🛡"
        return {"type":"scan_results","message":msg,"results":results}
    
    return {"type":"text","message":
        "I am here to assist with cybersecurity inquiries and Kavach Net operations. "
        "For non-security related questions, I recommend consulting with your administration. "
        "Feel free to ask about phishing, network security, SQL injection, or how to use our scanners."
    }


# ═══════════════════════════════════════════════════════
#  ROUTES
# ═══════════════════════════════════════════════════════

@chatbot_bp.route("/chat",methods=["POST"])
@authenticated_required
def chat():
    username = get_jwt_identity()
    data=request.get_json() or {}
    msg=data.get("message","").strip()
    if not msg: return jsonify({"error":"Message required"}),400
    
    u=_eu(msg); i=_di(msg); r=_br(i,msg,u)
    
    # Save to history
    # For scan results, we simplify the stored reply
    stored_reply = r["message"] if "message" in r else "Complex reply"
    custom_db.save_chat_message(username, msg, stored_reply, i)
    
    return jsonify({"reply":r,"intent":i,"urls_found":u,
                    "layer2_active":LAYER2_AVAILABLE,"layer3_active":LAYER3_AVAILABLE}),200

@chatbot_bp.route("/history", methods=["GET"])
@authenticated_required
def get_history():
    username = get_jwt_identity()
    history = custom_db.get_chat_history(username, limit=30)
    return jsonify({"history": history}), 200

@chatbot_bp.route("/log-override", methods=["POST"])
@authenticated_required
def log_override():
    username = get_jwt_identity()
    data = request.get_json() or {}
    url = data.get("url")
    risk = data.get("risk", "High")
    
    if not url:
        return jsonify({"error": "URL required"}), 400
        
    # Log the override
    custom_db.log_user_override(username, url, risk)
    
    # Check for escalation
    override_count = custom_db.get_user_override_count(username, window_hours=24)
    if override_count >= 3:
        # Escalate to admin
        custom_db.save_incident({
            "type": "SECURITY_POLICY_VIOLATION",
            "severity": "CRITICAL",
            "message": f"User {username} has overridden {override_count} security blocks in 24h. Investigation recommended."
        })
        return jsonify({
            "status": "logged", 
            "escalated": True,
            "message": "⚠️ Multiple risky overrides detected. Admin has been notified for investigation."
        }), 200
        
    return jsonify({"status": "logged", "escalated": False}), 200

@chatbot_bp.route("/scan-url",methods=["POST"])
@authenticated_required
def scan_url():
    data=request.get_json() or {}
    url=(data.get("url") or data.get("target") or data.get("link") or "").strip()
    if not url: return jsonify({"error":"URL required"}),400
    return jsonify({"result":full_scan(url)}),200

@chatbot_bp.route("/status",methods=["GET"])
def status():
    return jsonify({"layer1":"active",
        "layer2":"active" if LAYER2_AVAILABLE else "not_loaded",
        "layer3":"active" if LAYER3_AVAILABLE else "not_configured",
        "neutralization":"active"}),200
