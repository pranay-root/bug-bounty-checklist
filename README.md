Here's a **Bug Bounty General Checklist** to help you stay organized when testing for vulnerabilities in web applications, networks, or mobile apps.

---

## **🛠️ Reconnaissance**
- [ ] **Subdomain Enumeration** (e.g., `Subfinder`, `Amass`, `Assetfinder`)
- [ ] **Port Scanning** (e.g., `Nmap`, `Masscan`, `Rustscan`)
- [ ] **Directory & File Enumeration** (e.g., `ffuf`, `dirsearch`, `gobuster`)
- [ ] **Identify Technologies** (e.g., `WhatWeb`, `Wappalyzer`, `BuiltWith`)
- [ ] **Check for Public Exposed Files** (`robots.txt`, `.git/`, `.env`, `.DS_Store`, `.htaccess`, `backup.zip`)

---

## **🔐 Authentication & Authorization**
- [ ] **Test for Weak Credentials** (default, common, leaked passwords)
- [ ] **Brute Force Login** (`Hydra`, `Burp Intruder`, `wfuzz`)
- [ ] **Check for Rate Limiting** (rapid login attempts)
- [ ] **2FA/OTP Bypass** (resend codes, brute-force, social engineering)
- [ ] **Session Hijacking & Fixation** (stealing session tokens)
- [ ] **JWT Token Manipulation** (none algorithm, key disclosure, tampering)
- [ ] **Check for IDOR (Insecure Direct Object References)** (accessing unauthorized data)

---

## **📦 Web Vulnerabilities**
- [ ] **SQL Injection (SQLi)** (`sqlmap`, manual payload testing)
- [ ] **Cross-Site Scripting (XSS)** (reflected, stored, DOM-based)
- [ ] **Cross-Site Request Forgery (CSRF)** (check for missing CSRF tokens)
- [ ] **Server-Side Request Forgery (SSRF)** (check URL parameters)
- [ ] **Command Injection** (`; ls`, `| whoami`, `; cat /etc/passwd`)
- [ ] **Local File Inclusion (LFI)** (`../../etc/passwd`, PHP wrappers)
- [ ] **Remote File Inclusion (RFI)** (uploading malicious files)
- [ ] **XML External Entity (XXE) Injection** (testing XML parsing)
- [ ] **Deserialization Attacks** (Python Pickle, PHP unserialize)
- [ ] **CORS Misconfigurations** (`Access-Control-Allow-Origin: *`)

---

## **📡 API Testing**
- [ ] **Check for Open Endpoints** (`swagger.json`, `api-docs`)
- [ ] **Test for Broken Access Controls** (admin endpoints accessible?)
- [ ] **Check for Rate Limits** (`Burp Intruder`, `ffuf`)
- [ ] **Parameter Tampering** (`id=123` → `id=124` or `id=1 OR 1=1`)
- [ ] **Check for API Keys in Responses** (`apikey=12345`)
- [ ] **Check GraphQL for Misconfigurations** (`Introspection Query`, `graphql-voyager`)

---

## **📲 Mobile Application Testing**
- [ ] **Decompile APK/IPA** (`jadx`, `apktool`, `mobSF`)
- [ ] **Check for Hardcoded Secrets** (`grep` sensitive strings)
- [ ] **Test WebViews for XSS** (`javascript:alert(1)`)
- [ ] **Check Local Storage for Sensitive Data** (`SharedPreferences`, `Keychain`)
- [ ] **Network Traffic Analysis** (`Burp Suite`, `mitmproxy`)
- [ ] **SSL Pinning Bypass** (`Frida`, `Objection`, `SSL Kill Switch`)

---

## **💻 Infrastructure & Cloud Testing**
- [ ] **Scan for Open Ports** (`Nmap`, `Shodan`, `Censys`)
- [ ] **Check for Misconfigured AWS S3 Buckets** (`aws s3 ls s3://target-bucket`)
- [ ] **Identify Leaked Credentials** (`GitHub dorks`, `Google Dorks`)
- [ ] **Check for Exposed Services** (`Redis`, `Elasticsearch`, `MongoDB`)
- [ ] **Check for Weak SSH/FTP Credentials** (`hydra`, `medusa`)

---

## **📂 Data Leakage**
- [ ] **Search for Sensitive Files** (`backup.zip`, `.git/`, `.svn/`)
- [ ] **Look for API Keys and Tokens** (e.g., exposed in JavaScript files)
- [ ] **Google Dorking** (`site:target.com ext:log`, `site:pastebin.com target`)

---

## **🛑 Denial of Service (DoS)**
- [ ] **Test for Rate Limit Bypass** (high request volume)
- [ ] **Check for Slowloris or HTTP Flood Attacks** (`slowloris`, `hping3`)
- [ ] **Test for XML Bombs** (`<!DOCTYPE foo [<!ENTITY a "AAAAA...">]>`)

---

## **📊 Reporting**
- [ ] **Gather Proof of Concepts (PoCs)** (screenshots, request/response logs)
- [ ] **Provide Impact Analysis** (how severe is the bug?)
- [ ] **Suggest Remediation Steps** (how to fix the issue)
- [ ] **Format Report Clearly** (follow platform guidelines)

---

Here’s a **Bug Bounty Checklist** specifically for **Web Applications** and **APIs** to help streamline your testing process.  

---

# **🛠️ Web Application Bug Bounty Checklist**  

## **🔍 Reconnaissance**  
- [ ] **Subdomain Enumeration** (`subfinder`, `amass`, `assetfinder`)  
- [ ] **Identify Technologies** (`Wappalyzer`, `WhatWeb`, `BuiltWith`)  
- [ ] **Check for Publicly Exposed Files** (`robots.txt`, `.git/`, `.env`, `.DS_Store`, `.htaccess`)  
- [ ] **Directory & File Enumeration** (`ffuf`, `dirsearch`, `gobuster`)  
- [ ] **Parameter Discovery** (`ParamSpider`, `Arjun`)  

---

## **🔐 Authentication & Authorization Testing**  
- [ ] **Weak Credentials & Brute Force** (`admin/admin`, `password123`)  
- [ ] **Check for Default Credentials** (`hydra`, `wfuzz`)  
- [ ] **Check Rate Limiting on Login & OTP** (`Burp Intruder`, `ffuf`)  
- [ ] **Session Fixation & Hijacking** (Stealing/manipulating session cookies)  
- [ ] **JWT Token Tampering** (`none` algorithm, modifying payload)  
- [ ] **IDOR (Insecure Direct Object References)** (Accessing unauthorized data)  

---

## **⚠️ Web Vulnerabilities Testing**  
### **Injection Attacks**  
- [ ] **SQL Injection (SQLi)** (`sqlmap`, manual payloads)  
- [ ] **Command Injection** (`whoami`, `cat /etc/passwd`)  
- [ ] **LDAP & NoSQL Injection** (Bypassing login using MongoDB queries)  
- [ ] **Server-Side Template Injection (SSTI)** (`{{7*7}}`, `{{config}}`)  

### **Client-Side Attacks**  
- [ ] **Cross-Site Scripting (XSS)** (Reflected, Stored, DOM-based)  
- [ ] **Clickjacking** (`X-Frame-Options: DENY` check)  
- [ ] **CSRF (Cross-Site Request Forgery)** (Check for missing CSRF tokens)  
- [ ] **CORS Misconfigurations** (`Access-Control-Allow-Origin: *`)  

### **File Upload Testing**  
- [ ] **Check File Extension Bypass** (`.php`, `.jsp`, `.exe`)  
- [ ] **Upload Web Shell** (`PentestMonkey`, `.htaccess` tricks)  
- [ ] **Check for Content-Type Bypass** (`image/png` as `php`)  

### **Access Control & Privilege Escalation**  
- [ ] **Test User Roles & Privileges** (Guest vs Admin)  
- [ ] **Try Changing User ID in Requests** (`user_id=123 → user_id=124`)  
- [ ] **Bypass Restrictions (CORS, Rate Limits, Headers)**  

### **Server-Side Attacks**  
- [ ] **SSRF (Server-Side Request Forgery)** (`file://`, `gopher://`, `http://localhost`)  
- [ ] **XXE (XML External Entity Injection)** (`<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>`)  
- [ ] **Deserialization Attacks** (`pickle`, `PHP unserialize`, `Java deserialization`)  

---

## **🌐 API Bug Bounty Checklist**  

### **🛠 API Reconnaissance & Discovery**  
- [ ] **Locate API Documentation** (`swagger.json`, `api-docs`)  
- [ ] **Check for Public API Endpoints** (`Wayback Machine`, `GitHub Dorks`)  
- [ ] **Identify API Technologies** (`GraphQL`, `REST`, `SOAP`)  

---

### **🛡️ API Security Testing**  
- [ ] **Check for Open Endpoints Without Authentication**  
- [ ] **Test for Broken Access Control** (`/admin`, `/users/export`)  
- [ ] **Parameter Tampering** (`id=123` → `id=124` or `id=1 OR 1=1`)  
- [ ] **Test for Rate Limiting** (`Burp Intruder`, `ffuf`)  
- [ ] **Check for API Keys in Responses** (`apikey=12345`, `token=abcdef`)  
- [ ] **JWT Token Manipulation** (`none` algorithm, modifying signature)  
- [ ] **Try Overwriting/Deleting Data Without Authorization** (`PUT`, `DELETE`)  

---

### **🔗 API Injection & Exploitation**  
- [ ] **SQL Injection (SQLi) in API Requests** (`' OR 1=1--`, `UNION SELECT`)  
- [ ] **XSS in API Responses** (`JSON responses reflecting user input`)  
- [ ] **SSRF via API Calls** (`http://localhost/admin`)  
- [ ] **GraphQL Misconfigurations** (`Introspection query`, `GraphQL Voyager`)  

---

### **📂 Data Leakage & Misconfigurations**  
- [ ] **Look for Sensitive Data Exposure** (Emails, user tokens, passwords)  
- [ ] **Check for Hardcoded API Keys in JavaScript Files**  
- [ ] **Search for Private Data in API Responses** (`/me`, `/admin/settings`)  
- [ ] **Test for CORS Misconfigurations** (`Access-Control-Allow-Origin: *`)  

---

## **🛑 Denial of Service (DoS) Testing**  
- [ ] **Check for Rate Limit Bypass** (`X-Forwarded-For`, `X-Real-IP`)  
- [ ] **Try Sending Large Payloads** (`JSON bomb`, `XXE entity expansion`)  
- [ ] **Slowloris or HTTP Flood Attack** (`slowloris`, `hping3`)  

---

## **📊 Reporting & Proof of Concept (PoC)**  
- [ ] **Collect Evidence (Screenshots, Request/Response Logs)**  
- [ ] **Document Impact & Severity**  
- [ ] **Suggest Remediation Steps**  
- [ ] **Format Report Clearly (Follow Bug Bounty Platform Guidelines)**  

---

This checklist covers the most critical vulnerabilities for **web applications** and **APIs**. 
Note: Make sure to check the platform rules and remove any checklist accordingly.
