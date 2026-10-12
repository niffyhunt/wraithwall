# Security Report

**Scanned:** <TS>
**Schema version:** 1
**Total findings:** 6
- 🔴 Critical: 3
- 🟠 High: 3
- 🟡 Medium: 0
- 🟢 Low: 0
- 🔵 Info: 0

## Findings by Severity

### 🔴 CRITICAL

#### Hardcoded secret detected: API key literal
**CWE:** CWE-798 — Hardcoded Credentials
**Confidence:** Confidence.LOW

A potential API key literal was detected in source code. Shannon entropy: 3.6. Secrets in source code can be exposed through version control.

**Evidence:** Pattern 'API key literal' matched at app.py:10 (entropy 3.6)
**File:** `app.py`
**Lines:** [10]

**Exploitation Scenario:** If this code is committed to a repository, anyone with access can extract the credential.

**Recommendation:** Move the secret to an environment variable or a secrets manager. Use os.environ.get() or a .env file that is gitignored.
**Finding ID:** `rf-3b246cba916cdc2dc3371cf4` | **State:** new
**Analyzer:** hardcoded_secret

#### Dangerous eval() call
**CWE:** CWE-95 — Improper Neutralization of Directives in Dynamically Evaluated Code
**Confidence:** Confidence.HIGH

eval() can execute arbitrary Python code. If any part of the input is user-controlled, this is a critical vulnerability.

**Evidence:** Found at app.py:18
**File:** `app.py`
**Lines:** [18]

**Exploitation Scenario:** An attacker can supply a malicious string to eval() and achieve arbitrary code execution.

**Recommendation:** Remove eval() entirely. If dynamic evaluation is needed, use ast.literal_eval() for safe data structures, or a domain-specific parser.
**Finding ID:** `rf-21f22d380554358c1fffd899` | **State:** new
**Analyzer:** eval_exec

#### [JS/TS] eval() call
**CWE:** CWE-94 — Improper Control of Generation of Code
**Confidence:** Confidence.HIGH

eval() executes arbitrary JavaScript code. Use JSON.parse() for data or avoid dynamic code execution entirely.

**Evidence:** Pattern 'eval() call' matched at web.js:9
**File:** `web.js`
**Lines:** [9]

**Exploitation Scenario:** https://cwe.mitre.org/data/definitions/94.html

**Recommendation:** Apply secure coding practices for JavaScript/Node.js.
**Finding ID:** `rf-a93248f2241e98f99bef9609` | **State:** new
**Analyzer:** javascript

### 🟠 HIGH

#### Weak cryptography: MD5 hashing
**CWE:** CWE-327 — Use of a Broken or Risky Cryptographic Algorithm
**Confidence:** Confidence.HIGH

Usage of MD5 hashing detected. This is cryptographically weak or broken.

**Evidence:** Found in app.py:22
**File:** `app.py`
**Lines:** [22]

**Exploitation Scenario:** Attackers can exploit weak hashing to perform collision attacks or brute-force hashed values.

**Recommendation:** Replace MD5 hashing with a modern alternative (e.g., hashlib.sha256, secrets module, AES-GCM).
**Finding ID:** `rf-6930fd27d0ce4048f0278843` | **State:** new
**Analyzer:** weak_crypto

#### Potential command injection via os.system/os.popen
**CWE:** CWE-78 — Improper Neutralization of Special Elements used in an OS Command
**Confidence:** Confidence.MEDIUM

Using os.system() or os.popen() with unsanitized input can lead to command injection.

**Evidence:** Found at app.py:14
**File:** `app.py`
**Lines:** [14]

**Exploitation Scenario:** If user input reaches os.system(), an attacker can inject arbitrary shell commands.

**Recommendation:** Use subprocess.run() with a list of arguments and shell=False instead.
**Finding ID:** `rf-4a7b081572995cafc3c9b105` | **State:** new
**Analyzer:** command_injection

#### [JS/TS] .innerHTML assignment
**CWE:** CWE-79 — Improper Neutralization of Input During Web Page Generation
**Confidence:** Confidence.HIGH

Unsanitized innerHTML can lead to XSS. Use textContent or DOM APIs with sanitization.

**Evidence:** Pattern '.innerHTML assignment' matched at web.js:5
**File:** `web.js`
**Lines:** [5]

**Exploitation Scenario:** https://cwe.mitre.org/data/definitions/79.html

**Recommendation:** Apply secure coding practices for JavaScript/Node.js.
**Finding ID:** `rf-91795fee97db65968c3d9cc6` | **State:** new
**Analyzer:** javascript

## Dependency Reachability
- `flask` — **unknown_reachability** (low)
- `requests` — **unknown_reachability** (low)