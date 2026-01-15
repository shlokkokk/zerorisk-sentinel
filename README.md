# ZeroRisk Sentinel 

ZeroRisk Sentinel is an academic cybersecurity project designed to demonstrate how static analysis, heuristic detection, and behavioral inference can be used to identify potential digital risks before execution.

The project focuses on explainable, offline-first security analysis of files, URLs, and mobile applications for learning, demonstration, and academic evaluation purposes.

---
https://cyberthon-zeta.vercel.app/

## Core Methodology

ZeroRisk Sentinel follows a pre-execution security analysis approach built around:

- Static inspection (no execution or sandboxing)
- Rule-based and heuristic detection
- Behavioral inference from observed indicators
- Optional AI-assisted explanations for interpretability

Detection decisions are explainable and based on observable signals rather than black-box classification.

---

## Analysis Scope & Limitations

- Performs **static analysis only**
- No file execution, URL visiting, or OS interaction
- No live browsing, sandboxing, or emulation
- Detection results are **heuristic-based indicators**, not definitive proof
- Does **not** replace antivirus or enterprise security solutions
- Designed strictly for **learning, demonstration, and academic use**

---

## Analysis Modes

- **Quick Scan**  
  Performs fast, strategic sampling of file content for rapid risk awareness.

- **Deep Scan (Demo Mode)**  
  Streams and inspects full file content in chunks for extended heuristic analysis.  
  Intended for controlled demonstrations and evaluation scenarios.

Scan mode selection is fully user-controlled.

---

## File Security Analysis

### Header & Signature Inspection
- Magic byte verification
- Extension mismatch detection
- Spoofing and RTL override detection

### Malware & Spyware Indicators
- Suspicious code patterns
- Command execution functions
- Registry and system modification indicators
- Network and data exfiltration patterns

### Keylogger & Surveillance Detection
- Keyboard hook indicators
- API call pattern inspection
- Stealth and monitoring behavior inference

### Permission & Risk Inference
- Privilege escalation indicators
- Persistence behavior patterns
- Risk scoring based on inferred intent

---

## APK Static Analysis

Android application packages (APKs) are inspected using static metadata and permission analysis.

- Manifest extraction
- High-risk permission detection
- Permission combination risk scoring
- No execution, emulation, or runtime monitoring

APK analysis is performed using a Python-based backend and remains strictly static.

---

## URL Security Analysis Module

The URL analysis module applies weighted heuristic rules to identify potentially deceptive or suspicious links commonly used in phishing attacks.

### Analysis Techniques
- Protocol and HTTPS validation
- IP-based and shortened URL detection
- Suspicious domain and TLD patterns
- Phishing keyword and impersonation indicators
- Structural and query parameter inspection

No live website access, redirection, DNS lookup, or reputation querying is performed.

---

## Heuristic & Behavioral Correlation

Detected indicators are correlated using a rule-driven heuristic engine to infer overall threat confidence.

- Multi-signal correlation
- Weighted behavior scoring
- Normalized confidence levels
- Explainable decision logic

An optional AI-assisted explanation layer converts final results into human-readable security insights.  
The AI component does **not** influence detection logic or scoring.

---

## System Workflow

1. User submits a file or URL
2. Static data is extracted without execution
3. Heuristic rules and indicators are applied
4. Risk scores and threat levels are calculated
5. Findings are correlated into a behavior profile
6. Results are presented with explanations

---

## Architecture Philosophy

ZeroRisk Sentinel is designed as a hybrid-ready system.

- Client-side analysis remains the primary and fail-safe layer
- Offline-first with zero data exposure
- Optional backend services enhance depth without replacing local analysis
- AI explanations remain optional and non-blocking

---

## Deployment

- Frontend: Demo-hosted for academic evaluation
- Backend: Hosted on Render (demo environment only)

---

## Security & Privacy

- All analysis is performed locally
- No files or URLs are permanently stored
- No tracking, telemetry, or background data collection
- Session-based, temporary analysis only

---

## Project Purpose

- Study static and heuristic cybersecurity techniques
- Understand spyware and phishing indicators
- Demonstrate explainable security analysis
- Support academic learning and cyberthon evaluation

---

© 2025 ZeroRisk Sentinel  
Academic cybersecurity analysis project


