import hashlib
import json
import os
import re
import xml.etree.ElementTree as ET
from datetime import datetime
import feedparser
import requests

# Fallback feeds if OPML fails
FALLBACK_FEEDS = {
    "Recorded Future": "https://www.recordedfuture.com/feed",
    "CISA Cyber Alerts": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
    "The DFIR Report": "https://thedfirreport.com/feed/",
    "Red Canary": "https://redcanary.com/blog/feed/"
}

# 1. Watchlist split into "My Stack" (Identity/Cloud) and "Active Exploitation"
MY_STACK_KEYWORDS = [
    r"\bokta\b", r"\bactive directory\b", r"\baad\b", r"\bentra\b",
    r"\baws\b", r"\bazure\b", r"\bsailpoint\b", r"\bidentitynow\b",
    r"\bmfa\b", r"\boauth\b", r"\bsso\b", r"\bsaml\b"
]

EXPLOIT_KEYWORDS = [
    r"\bzero-day\b", r"\b0-day\b", r"\bactively exploited\b", r"\bin the wild\b",
    r"\brce\b", r"\bcredential stuffing\b", r"\btoken theft\b", r"\bransomware\b", r"\bgenesis\b"
]

DB_FILE = "seen_intel.json"
OPML_FILE = "feeds.opml"
BRIEFING_FILE = "DAILY_BRIEFING.md"
WEB_JSON_FILE = "feeds_data.json"
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
GITHUB_REPO = os.getenv("GITHUB_REPOSITORY")

def load_database():
    if os.path.exists(DB_FILE):
        try:
            with open(DB_FILE, "r") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def save_database(data):
    with open(DB_FILE, "w") as f:
        json.dump(data, f, indent=2)

def load_cisa_kev():
    """Fetches CISA Known Exploited Vulnerabilities catalog for instant CVE enrichment."""
    kev_map = {}
    try:
        url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        resp = requests.get(url, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            for v in data.get("vulnerabilities", []):
                cve_id = v.get("cveID")
                if cve_id:
                    kev_map[cve_id] = {
                        "vendor": v.get("vendorProject"),
                        "product": v.get("product"),
                        "ransomware": v.get("knownRansomwareCampaignUse", "Unknown")
                    }
            print(f"[+] Loaded {len(kev_map)} CVEs from CISA KEV catalog.")
    except Exception as e:
        print(f"[-] CISA KEV fetch warning: {e}")
    return kev_map

def get_epss_scores(cve_list):
    """Queries FIRST.org EPSS API for probability of exploitation in next 30 days."""
    if not cve_list:
        return {}
    epss_map = {}
    try:
        joined = ",".join(cve_list[:20])
        url = f"https://api.first.org/data/v1/epss?cve={joined}"
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            for item in resp.json().get("data", []):
                epss_map[item["cve"]] = float(item.get("epss", 0.0))
    except Exception as e:
        print(f"[-] EPSS lookup warning: {e}")
    return epss_map

def extract_iocs_and_ttps(text):
    """Extracts CVEs, MITRE ATT&CK techniques, and SHA-256 hashes."""
    cves = sorted(list(set(re.findall(r"CVE-\d{4}-\d{4,7}", text, flags=re.IGNORECASE))))
    cves = [c.upper() for c in cves]
    mitre = sorted(list(set(re.findall(r"\bT1\d{3}(?:\.\d{3})?\b", text))))
    sha256 = sorted(list(set(re.findall(r"\b[a-fA-F0-9]{64}\b", text))))
    return cves, mitre, sha256

def is_near_duplicate(title, cves, history):
    """Story clustering: drops syndicated repeats with >75% title word overlap or shared recent CVE."""
    words_new = set(re.findall(r"\b[a-z0-9]{4,}\b", title.lower()))
    for item in history.values():
        if not isinstance(item, dict):
            continue
        # 1. Check word overlap
        old_title = item.get("title", "")
        words_old = set(re.findall(r"\b[a-z0-9]{4,}\b", old_title.lower()))
        if words_new and words_old:
            overlap = len(words_new & words_old) / float(min(len(words_new), len(words_old)))
            if overlap >= 0.75:
                return True
        # 2. Check if we already alerted on this exact CVE
        old_cves = set(item.get("cves", []))
        if cves and old_cves and (set(cves) & old_cves):
            return True
    return False

def score_article(text, cves, mitre, kev_map, epss_map):
    """Calculates a 0-100 severity score inspired by jozeta/ThreatFeed."""
    text_lower = text.lower()
    stack_hits = [m for p in MY_STACK_KEYWORDS for m in re.findall(p, text_lower)]
    exploit_hits = [m for p in EXPLOIT_KEYWORDS for m in re.findall(p, text_lower)]
    stack_hits = sorted(list(set(stack_hits)))
    exploit_hits = sorted(list(set(exploit_hits)))

    score = 0
    if stack_hits:
        score += 35
    if exploit_hits:
        score += 25
    if cves:
        score += 15
    if mitre:
        score += 10

    in_kev = [c for c in cves if c in kev_map]
    max_epss = max([epss_map.get(c, 0.0) for c in cves], default=0.0)

    if in_kev:
        score += 40
    if max_epss >= 0.50:
        score += 20

    score = min(score, 100)
    if score >= 70 or in_kev:
        severity = "CRITICAL"
    elif score >= 45:
        severity = "HIGH"
    elif score >= 30:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    return score, severity, stack_hits, exploit_hits, in_kev, max_epss

def load_feeds_from_opml():
    if not os.path.exists(OPML_FILE):
        return FALLBACK_FEEDS
    feeds = {}
    try:
        with open(OPML_FILE, "r", encoding="utf-8", errors="ignore") as f:
            raw_content = f.read()
        sanitized = re.sub(r"&(?!amp;|lt;|gt;|apos;|quot;)", "&amp;", raw_content)
        root = ET.fromstring(sanitized)
        for outline in root.iter("outline"):
            title = outline.get("title") or outline.get("text")
            url = outline.get("xmlUrl")
            if url and title:
                skip = ["Washington Post", "The Atlantic", "Associated Press", "BBC News", "Android Authority", "Gear Latest"]
                if not any(k.lower() in title.lower() for k in skip):
                    feeds[title.strip()] = url.strip()
        return feeds if feeds else FALLBACK_FEEDS
    except Exception as e:
        print(f"[!] OPML Fallback: {e}")
        return FALLBACK_FEEDS

def create_github_issue(finding):
    if not GITHUB_TOKEN or not GITHUB_REPO:
        return
    url = f"https://api.github.com/repos/{GITHUB_REPO}/issues"
    headers = {"Authorization": f"token {GITHUB_TOKEN}", "Accept": "application/vnd.github.v3+json"}

    kev_badge = f"🔥 **YES ({', '.join(finding['in_kev'])})**" if finding["in_kev"] else "No"
    epss_str = f"{finding['max_epss']*100:.1f}%" if finding["cves"] else "N/A"
    mitre_str = ", ".join(finding["mitre"]) if finding["mitre"] else "None explicitly cited"

    body = (
        f"### 🚨 Threat Intelligence Enrichment Summary\n"
        f"| Field | Value |\n"
        f"|---|---|\n"
        f"| **Severity & Score** | **{finding['severity']} ({finding['score']}/100)** |\n"
        f"| **Source Feed** | {finding['source']} |\n"
        f"| **My Stack Matches** | `{', '.join(finding['stack_hits']).upper() or 'GENERAL'}` |\n"
        f"| **Exploit Indicators** | `{', '.join(finding['exploit_hits']).upper() or 'NONE'}` |\n"
        f"| **Extracted CVEs** | `{', '.join(finding['cves']) or 'None'}` |\n"
        f"| **CISA KEV Listed?** | {kev_badge} |\n"
        f"| **Max EPSS Probability (30d)** | `{epss_str}` |\n"
        f"| **MITRE ATT&CK IDs** | `{mitre_str}` |\n\n"
        f"🔗 **Original Report:** [{finding['title']}]({finding['link']})\n\n"
        f"### 🎯 L3 Hunt & Triage Checklist\n"
        f"1. **Asset/Stack Validation:** Verify exposure across Identity/Cloud assets.\n"
        f"2. **SIEM Pivot:** Hunt across `okta`, `identity_now`, `cloudtrail`, and `crowdstrike` indices.\n"
        f"3. **Purple Team:** Evaluate extracted ATT&CK techniques (`{mitre_str}`) for detection coverage.\n"
    )

    labels = ["adversary-intel", f"severity:{finding['severity'].lower()}"]
    if finding["in_kev"]:
        labels.append("cisa-kev")

    payload = {
        "title": f"[{finding['severity']} | {finding['score']}] {finding['title'][:75]}",
        "body": body,
        "labels": labels
    }
    try:
        requests.post(url, json=payload, headers=headers, timeout=10)
    except Exception as e:
        print(f"[!] Issue error: {e}")

def update_daily_briefing(findings):
    """Generates a clean Markdown dashboard in the repo root (inspired by ThreatFeed Briefing)."""
    if not findings:
        return
    lines = [
        "# 🗞️ Daily Adversary Intelligence Briefing",
        f"*Last Updated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')} | TLP:AMBER*\n",
        "| Severity | Score | Source | Headline | CVEs / KEV | Stack Tags |",
        "|---|---|---|---|---|---|"
    ]
    for f in sorted(findings, key=lambda x: x["score"], reverse=True):
        cve_col = ", ".join(f["cves"]) + (" 🔥**(KEV)**" if f["in_kev"] else "")
        stack_col = ", ".join(f["stack_hits"]).upper() or "Threat"
        lines.append(f"| **{f['severity']}** | `{f['score']}` | {f['source']} | [{f['title'][:55]}...]({f['link']}) | {cve_col or '-'} | `{stack_col}` |")

    with open(BRIEFING_FILE, "w", encoding="utf-8") as out:
        out.write("\n".join(lines) + "\n")

def update_web_json(new_findings):
    """Maintains a rolling 200-item feeds_data.json file for the GitHub Pages website."""
    existing = []
    if os.path.exists(WEB_JSON_FILE):
        try:
            with open(WEB_JSON_FILE, "r", encoding="utf-8") as f:
                existing = json.load(f).get("items", [])
        except Exception:
            existing = []

    # Prepend new findings and deduplicate by link
    combined = new_findings + existing
    seen_links = set()
    deduped = []
    for item in combined:
        if item["link"] not in seen_links:
            seen_links.add(item["link"])
            deduped.append(item)

    deduped.sort(key=lambda x: x.get("score", 0), reverse=True)
    payload = {
        "updated_utc": datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
        "items": deduped[:200]
    }
    with open(WEB_JSON_FILE, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

def execute_pipeline():
    history = load_database()
    kev_map = load_cisa_kev()
    feeds = load_feeds_from_opml()
    new_findings = []

    for feed_name, url in feeds.items():
        try:
            parsed = feedparser.parse(url)
            for entry in parsed.entries[:15]:
                title = entry.get("title", "").strip()
                link = entry.get("link", "").strip()
                summary = entry.get("summary", "")
                if not title or not link:
                    continue

                item_hash = hashlib.sha256(f"{title.lower()}_{link.lower()}".encode("utf-8")).hexdigest()
                if item_hash in history:
                    continue

                full_text = f"{title} {summary}"
                cves, mitre, _ = extract_iocs_and_ttps(full_text)

                if is_near_duplicate(title, cves, history):
                    history[item_hash] = {"title": title, "cves": cves, "seen_at": datetime.utcnow().isoformat()}
                    continue

                epss_map = get_epss_scores(cves) if cves else {}
                score, severity, stack_hits, exploit_hits, in_kev, max_epss = score_article(
                    full_text, cves, mitre, kev_map, epss_map
                )

                # Capture findings for web dashboard
                if score >= 25:
                    finding = {
                        "source": feed_name, "title": title, "link": link,
                        "score": score, "severity": severity, "stack_hits": stack_hits,
                        "exploit_hits": exploit_hits, "cves": cves, "in_kev": in_kev,
                        "max_epss": max_epss, "mitre": mitre,
                        "detected_utc": datetime.utcnow().isoformat()
                    }
                    new_findings.append(finding)
                    
                    # Raise GitHub Triage Issues for scores >= 45
                    if score >= 45:
                        create_github_issue(finding)

                history[item_hash] = {"title": title, "cves": cves, "seen_at": datetime.utcnow().isoformat()}
        except Exception as e:
            print(f"[-] Skip {feed_name}: {e}")

    update_daily_briefing(new_findings)
    update_web_json(new_findings)
    save_database(history)
    print(f"[*] Completed. Dispatched {len(new_findings)} high/critical enriched findings.")

if __name__ == "__main__":
    execute_pipeline()
