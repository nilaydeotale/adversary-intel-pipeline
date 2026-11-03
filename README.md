# 🛡️ Adversary Intelligence Radar & Automated Triage Platform

[![Live Dashboard](https://img.shields.io/badge/Live_Dashboard-GitHub_Pages-10b981?logo=github&logoColor=white)](https://nilay-deotale-sp.github.io/adversary-intel-pipeline/)
![Python](https://img.shields.io/badge/Python-3.11-blue?logo=python&logoColor=white)
![GitHub Actions](https://img.shields.io/badge/Automation-Hourly_Cron-2088FF?logo=github-actions&logoColor=white)
![Enrichment](https://img.shields.io/badge/Enrichment-CISA_KEV_%7C_EPSS_%7C_ATT%26CK-purple)
![TLP](https://img.shields.io/badge/TLP-AMBER-orange)

An automated, serverless **Cyber Threat Intelligence (CTI)** aggregation, enrichment, and triage platform built to support **Threat-Informed Defense**. 

Every hour, this pipeline ingests 30+ high-signal security feeds, deduplicates syndicated stories via fuzzy clustering, enriches CVEs with live **CISA Known Exploited Vulnerabilities (KEV)** and **FIRST.org EPSS** exploit-probability telemetry, maps behaviors to **MITRE ATT&CK**, opens prioritized **GitHub Issues** for high-severity hits, and publishes a live dark-mode web radar via **GitHub Pages**.

👉 **Live Threat Radar Dashboard:** **[https://nilay-deotale-sp.github.io/adversary-intel-pipeline/](https://nilay-deotale-sp.github.io/adversary-intel-pipeline/)**  
👉 **24-Hour Executive Summary:** **[View `DAILY_BRIEFING.md`](./DAILY_BRIEFING.md)**

---

## 🎯 Executive Summary (BLUF)

Security Operations (SOC), Vulnerability Management (VM), and Red Teams face severe alert fatigue from raw RSS feeds and unprioritized CVE backlogs. This platform solves the **"Collection-to-Action" gap** with zero infrastructure overhead:

* **100% Serverless & Zero-Cost:** Runs hourly on GitHub Actions (`ubuntu-latest`) and hosts a static dark-mode web UI via GitHub Pages.
* **Multi-Source OPML Ingestion:** Dynamically parses 30+ curated threat research feeds from `feeds.opml` (Recorded Future Insikt Group, CISA, The DFIR Report, Red Canary, Unit 42, Google TAG, Cisco Talos, Wiz, etc.).
* **Two-Tier Deduplication (Hash + Story Clustering):** Combines `SHA-256` URL/title hashing (`seen_intel.json`) with **>75% word-overlap fuzzy matching and shared-CVE clustering** so syndicated news only triggers once.
* **Automated Vulnerability & TTP Enrichment:**
  * 🔥 **CISA KEV API:** Flags vulnerabilities confirmed as actively exploited in the wild or used in ransomware campaigns.
  * 📈 **FIRST.org EPSS API:** Pulls 30-day exploitation probability scores for every extracted `CVE-YYYY-NNNNN`.
  * 🎯 **MITRE ATT&CK & IOC Extraction:** Automatically extracts ATT&CK Technique IDs (`T1xxx.xxx`), CVEs, and `SHA-256` file hashes.
* **Weighted Severity Scoring (0–100):** Evaluates threats across enterprise Identity & Cloud stacks (`Okta`, `Entra/AAD`, `SailPoint/IdentityNow`, `AWS`, `OAuth`, `MFA`, `SAML`) to classify items as `CRITICAL`, `HIGH`, `MEDIUM`, or `LOW`.
* **Automated Case Management:** Automatically opens labeled GitHub Triage Issues (`severity:critical`, `cisa-kev`, `adversary-intel`) for items scoring $\ge 45/100$.

---

## 🏗️ End-to-End Architecture

```text
+-----------------------------------------------------------------------------+
|                           1. COLLECTION LAYER                               |
|     feeds.opml (30+ Feeds: Recorded Future, CISA, DFIR Report, Unit 42)     |
+-----------------------------------------------------------------------------+
                                       |
                                       v
+-----------------------------------------------------------------------------+
|                2. DEDUPLICATION & FUZZY STORY CLUSTERING                    |
|   SHA-256 State Check (seen_intel.json) + >75% Title Overlap / Shared CVE   |
+-----------------------------------------------------------------------------+
                                       |
                                       v
+-----------------------------------------------------------------------------+
|                  3. AUTOMATED CTI ENRICHMENT & SCORING                      |
|   * Regex Extraction : CVEs, MITRE ATT&CK IDs (T1xxx), SHA-256 Hashes       |
|   * Live API Lookups : CISA KEV Catalog + FIRST.org EPSS Probability API    |
|   * Weighted Scoring : 0-100 Score (Stack Match + Exploit Status + KEV)     |
+-----------------------------------------------------------------------------+
                                       |
            +--------------------------+--------------------------+
            | (Score >= 25)                                       | (Score >= 45)
            v                                                     v
+---------------------------------------+     +-------------------------------+
|     4A. LIVE WEB RADAR & BRIEFING     |     |   4B. SOC / CTI CASE QUEUE    |
| * Updates feeds_data.json (Top 200)   |     | * Opens GitHub Triage Issue   |
| * Renders index.html (GitHub Pages)   |     | * Applies Severity/KEV Labels |
| * Generates DAILY_BRIEFING.md Table   |     | * Sends Real-Time Email Alert |
+---------------------------------------+     +-------------------------------+

---
