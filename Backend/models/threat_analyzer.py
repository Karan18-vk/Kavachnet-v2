import random, datetime
from dataclasses import dataclass, field
from typing import List, Dict

KNOWN_MALICIOUS = ["45.95.","185.220.","194.165.","91.108.","23.129.","104.244."]
PRIVATE_RANGES  = ["10.","192.168.","172.16.","127.","::1"]

@dataclass
class ThreatResult:
    ip_address: str
    threat_type: str
    severity: str
    confidence: float
    risk_score: int
    flags: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    def to_dict(self):
        return {"ip_address": self.ip_address, "threat_type": self.threat_type,
                "severity": self.severity, "confidence": round(self.confidence*100,1),
                "risk_score": self.risk_score, "flags": self.flags,
                "recommendations": self.recommendations}

def analyze_ip(ip):
    for priv in PRIVATE_RANGES:
        if ip.startswith(priv):
            return ThreatResult(ip,"clean","low",0.98,2,["Private IP"],["No action required"])
    score, flags = 0, []
    for bad in KNOWN_MALICIOUS:
        if ip.startswith(bad):
            flags.append(f"Known malicious range ({bad}*)"); score += 60; break
    score = min(score + random.randint(0,15), 100)
    if score >= 60:
        threat, sev, conf = "c2", "critical", 0.80
        flags.append("Potential C2 traffic source")
        recs = ["Block IP immediately","Investigate all connections","Check lateral movement"]
    elif score >= 40:
        threat, sev, conf = "suspicious", "high", 0.65
        recs = ["Rate-limit this IP","Monitor closely","Consider temporary block"]
    elif score >= 20:
        threat, sev, conf = "suspicious", "medium", 0.50
        recs = ["Monitor this IP","Log all requests"]
    else:
        threat, sev, conf = "clean", "low", 0.90
        recs = ["No immediate action required"]
    return ThreatResult(ip, threat, sev, conf, score, flags, recs)

def analyze_log_events(events):
    results = {"total_events": len(events), "threats_detected": [], "summary": {}, "risk_level": "low"}
    if not events: return results
    ip_events = {}
    for ev in events:
        ip = ev.get("ip","unknown"); ip_events.setdefault(ip,[]).append(ev)
    threats = []
    for ip, evs in ip_events.items():
        failed = sum(1 for e in evs if "fail" in str(e.get("action","")).lower())
        ports  = set(e.get("port") for e in evs if e.get("port"))
        if failed >= 5:
            threats.append({"type":"brute_force","ip":ip,
                "severity":"high" if failed>=10 else "medium",
                "detail":f"{failed} failed logins from {ip}",
                "recommendation":f"Block {ip} and reset affected accounts"})
        if len(ports) >= 8:
            threats.append({"type":"port_scan","ip":ip,"severity":"high",
                "detail":f"Port scan from {ip} — {len(ports)} ports probed",
                "recommendation":f"Block {ip} at firewall immediately"})
    results["threats_detected"] = threats
    results["summary"] = {"unique_ips":len(ip_events),
        "brute_force_count": sum(1 for t in threats if t["type"]=="brute_force"),
        "port_scan_count":   sum(1 for t in threats if t["type"]=="port_scan")}
    results["risk_level"] = ("critical" if any(t["severity"]=="critical" for t in threats)
        else "high" if any(t["severity"]=="high" for t in threats)
        else "medium" if threats else "low")
    return results

def generate_threat_feed(institution_id=None):
    types = [
        ("Phishing Campaign","phishing","high","Mass phishing campaign targeting institutions."),
        ("Brute Force SSH","brute_force","medium","Automated SSH brute-force from botnet range."),
        ("Ransomware IOC","malware","critical","Ransomware C2 beacon in DNS traffic."),
        ("Port Scan","port_scan","medium","Systematic port reconnaissance from external host."),
        ("Zero-Day Probe","zero_day","critical","Exploit attempt matching new CVE signature."),
        ("Credential Stuffing","brute_force","high","Large-scale credential stuffing detected."),
        ("Data Exfiltration","anomaly","critical","Unusual outbound data to unknown host."),
    ]
    now  = datetime.datetime.utcnow()
    feed = []
    for i in range(10):
        tt = random.choice(types)
        feed.append({"id":1000+i,"title":tt[0],"threat_type":tt[1],"severity":tt[2],
            "description":tt[3],
            "source_ip":f"{random.randint(45,220)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}",
            "confidence":round(random.uniform(0.65,0.99)*100,1),
            "timestamp":(now-datetime.timedelta(minutes=random.randint(1,480))).isoformat()})
    return sorted(feed, key=lambda x: x["timestamp"], reverse=True)
