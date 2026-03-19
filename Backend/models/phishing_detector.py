import re, math, urllib.parse
from dataclasses import dataclass, field
from typing import List

PHISHING_KEYWORDS = ["login","signin","verify","account","update","secure","banking",
    "paypal","apple","amazon","microsoft","google","netflix","confirm","suspended",
    "unusual","activity","password","credential","wallet","crypto","urgent","alert",
    "click","limited","free","prize","winner"]
SUSPICIOUS_TLDS = [".tk",".ml",".ga",".cf",".gq",".xyz",".top",".club",".online",
    ".site",".live",".click",".download",".loan",".stream",".work",".trade",".win"]
TRUSTED_DOMAINS = ["google.com","github.com","microsoft.com","apple.com","amazon.com",
    "paypal.com","wikipedia.org","youtube.com","facebook.com","linkedin.com","twitter.com","x.com"]
IP_PATTERN  = re.compile(r"https?://(\d{1,3}\.){3}\d{1,3}")
URL_SHORTEN = ["bit.ly","tinyurl.com","t.co","goo.gl","ow.ly","buff.ly","short.io","rebrand.ly"]

@dataclass
class PhishingResult:
    url: str
    verdict: str
    confidence: float
    risk_score: int
    flags: List[str] = field(default_factory=list)
    indicators: dict = field(default_factory=dict)
    def to_dict(self):
        return {"url": self.url, "verdict": self.verdict,
                "confidence": round(self.confidence * 100, 1),
                "risk_score": self.risk_score, "flags": self.flags,
                "indicators": self.indicators}

def _entropy(s):
    if not s: return 0.0
    freq = {}
    for c in s: freq[c] = freq.get(c, 0) + 1
    return -sum((f/len(s)) * math.log2(f/len(s)) for f in freq.values())

def analyze_url(raw_url):
    url = raw_url.strip()
    if not url.startswith(("http://","https://")): url = "http://" + url
    flags, score, details = [], 0, {}
    try:
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc.lower().replace("www.","")
        path   = parsed.path.lower()
        query  = parsed.query.lower()
        full   = (domain + path + query).lower()
    except:
        return PhishingResult(raw_url, "suspicious", 0.6, 55, ["URL could not be parsed"], {})
    for td in TRUSTED_DOMAINS:
        if domain == td or domain.endswith("." + td):
            return PhishingResult(raw_url, "safe", 0.95, 5, ["Trusted domain"], {"domain": domain})
    if IP_PATTERN.match(url):
        flags.append("IP address used as hostname"); score += 40; details["ip_host"] = True
    for s in URL_SHORTEN:
        if domain == s:
            flags.append(f"URL shortener: {s}"); score += 20; details["shortened"] = True; break
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            flags.append(f"High-risk TLD: {tld}"); score += 25; details["suspicious_tld"] = tld; break
    found_kw = [kw for kw in PHISHING_KEYWORDS if kw in full]
    if found_kw:
        score += min(len(found_kw)*8, 30)
        flags.append(f"Phishing keywords: {', '.join(found_kw[:5])}"); details["keywords"] = found_kw
    sub_count = len(domain.split(".")) - 2
    if sub_count > 2: score += 15; flags.append(f"Excessive subdomains ({sub_count})")
    if len(domain) > 40: score += 15; flags.append("Very long domain name")
    ent = _entropy(domain.split(".")[0]); details["domain_entropy"] = round(ent, 2)
    if ent > 3.8: score += 20; flags.append(f"High domain entropy ({ent:.2f})")
    if domain.count("-") >= 3: score += 10; flags.append("Many hyphens in domain")
    if parsed.scheme == "http": score += 10; flags.append("No HTTPS")
    if "@" in url: score += 30; flags.append("@ symbol in URL")
    score = min(score, 100)
    if score >= 60:   verdict, confidence = "malicious",  0.60 + (score-60)/250
    elif score >= 30: verdict, confidence = "suspicious", 0.40 + score/200
    else:             verdict, confidence = "safe",       1.0 - score/100
    confidence = round(min(confidence, 0.99), 3)
    if not flags: flags.append("No significant phishing indicators detected")
    return PhishingResult(raw_url, verdict, confidence, score, flags, details)
