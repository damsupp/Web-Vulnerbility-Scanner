# Reflected XSS & Input Sanitization Scanner

A lightweight, modular Python CLI tool designed to crawl web applications, detect forms, inject payloads, and audit inputs for Reflected Cross-Site Scripting (XSS) and input-sanitization vulnerabilities.

> [!WARNING]
> **LEGAL DISCLAIMER:** This tool is designed strictly for educational purposes, authorized penetration testing, and security auditing of systems you own or have explicit, written permission to test. Unauthorized scanning of third-party web applications is illegal. The author assumes no liability for misuse or damage caused by this program.

---

## 🚀 Features

* **Targeted Web Crawling:** Automatically extracts internal links within the same domain to map out attack surfaces up to a configurable depth.
* **Form Detection & Analysis:** Automatically parses HTML forms, extracting input fields (`text`, `search`, etc.) to map payload injection vectors.
* **Context-Based Payloads:** Tests against multiple payload variations targeting various HTML execution contexts.
* **Auto-Reporting:** Generates a clean text-based vulnerability report (`xss_report.txt`) listing vulnerable endpoints, methods used, and successful payloads.

---

## 🛠️ Installation & Setup

### Prerequisites
Make sure you have Python 3.x installed on your machine.

### 1. Clone the Repository
```bash
git clone [https://github.com/YOUR_USERNAME/YOUR_REPO_NAME.git](https://github.com/YOUR_USERNAME/YOUR_REPO_NAME.git)
cd YOUR_REPO_NAME
