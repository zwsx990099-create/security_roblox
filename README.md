# 🛡️ EDR Lua — Client-Side Behavioral Monitor

> **A Lua-based Event Detection & Response (EDR) system for Roblox.**
> Detects suspicious behavior in scripts running inside an executor environment — **without** touching memory, hooking the game's metatable, or violating Roblox ToS policies for client-side operations.

![Status](https://img.shields.io/badge/status-stable-green)
![Version](https://img.shields.io/badge/version-4.0.0-blue)
![Lua](https://img.shields.io/badge/lua-5.1%20%7C%20luau-blueviolet)
![License](https://img.shields.io/badge/license-MIT-orange)

---

## ⚠️ Disclaimer

**อ่านก่อนใช้งาน**

- เครื่องมือนี้เป็น **client-side behavioral monitor** เท่านั้น
- **ไม่ใช่ anti-cheat** และไม่สามารถป้องกัน server-side exploit ได้
- การใช้ **executor** ผิดต่อ [Roblox ToS](https://en.help.roblox.com/hc/en-us/articles/203313410) อยู่แล้ว
- เครื่องมือนี้ใช้เพื่อ **การศึกษาและวิจัยเท่านั้น**
- **ห้ามใช้ในเกม public** หรือในทางที่ละเมิดกฎของ Roblox
- ผู้พัฒนาไม่รับผิดชอบต่อการถูกแบนหรือความเสียหายใดๆ

---

## 📖 สารบัญ

1. [ภาพรวม](#-ภาพรวม)
2. [คุณสมบัติ](#-คุณสมบัติ)
3. [สถาปัตยกรรม](#-สถาปัตยกรรม)
4. [Quick Start](#-quick-start)
5. [การตั้งค่า](#%EF%B8%8F-การตั้งค่า)
6. [คำสั่ง](#-คำสั่ง)
7. [โหมด Performance](#-โหมด-performance)
8. [ToS Compliance](#-tos-compliance)
9. [Security](#-security)
10. [FAQ](#-faq)
11. [Troubleshooting](#-troubleshooting)
12. [Development](#-development)
13. [License](#-license)

---

## 🎯 ภาพรวม

**EDR Lua** คือระบบ monitoring พฤติกรรมของสคริปต์ Lua ที่รันอยู่ใน Roblox executor โดยใช้เทคนิคเดียวกับ EDR (Endpoint Detection & Response) ของ Windows:

| เทคนิค EDR | ในระบบนี้ |
|-------------|-----------|
| Kernel Callback | Opcode hook ผ่าน `debug.sethook` |
| ETW (Event Tracing) | Event Bus + Ring Buffer |
| WFP (Network Filter) | Network/HTTP hooks |
| Registry Filter | Global table monitor |
| AMSI (String Scanner) | String decrypt detector |
| Behavior Correlation | Markov chain + Pattern matcher |
| Risk Scoring | Bayesian + Adaptive thresholds |
| Detection Rules | YARA-style DSL (40+ rules) |
| Forensic Report | STIX 2.1, MITRE Navigator, SARIF |

### ใช้ทำอะไรได้

- ✅ วิเคราะห์สคริปต์ Lua ที่น่าสงสัย (obfuscated, stealer, RAT)
- ✅ ตรวจจับ behavior ที่ผิดปกติแบบ real-time
- ✅ สร้างรายงาน forensics (Markdown, JSON, STIX, SARIF)
- ✅ ศึกษาเทคนิค detection ในสภาพแวดล้อมที่ปลอดภัย

### ใช้ทำอะไรไม่ได้

- ❌ ป้องกัน server-side exploit
- ❌ ป้องกันผู้เล่นอื่นในเซิร์ฟเวอร์
- ❌ แทนที่ anti-cheat ของ Roblox
- ❌ ตรวจสอบโค้ด obfuscated แบบ 100% (Luraph v15 ยังคงท้าทาย)

---

## ✨ คุณสมบัติ

### 🎯 Core Detection
- **20+ Behavior Hooks** — ครอบคลุมทุก API ที่น่าสงสัย
- **40+ Built-in Rules** — พร้อมใช้ MITRE ATT&CK mapping
- **Real-Time Risk Scoring** — Bayesian + Adaptive thresholds
- **Multi-Engine Detection** — Markov chain, entropy, taint tracking
- **Attack Chain Reconstruction** — จับ kill chain stages

### 📊 Analysis
- **IOC Extractor** — URL, IP, hash, token, API key (13 ชนิด)
- **Forensic Timeline** — พร้อม clustering
- **Environment Diff** — snapshot ก่อน/หลัง
- **Statistical Scoring** — Shannon entropy, Z-score, KS test

### 📤 Export Formats (8 แบบ)
- Markdown, JSON, HTML, STIX 2.1, MITRE Navigator, CSV, SARIF, IOC TXT

### 🛡️ Safety & Compliance
- **ToS Policy Engine** — บล็อก operations ที่ผิดกฎ
- **Audit Log** — บันทึกทุก operation
- **Self-Integrity** — ตรวจ function tamper
- **Anti-Ban** — Session rotation + behavior normalizer
- **SHA-256 Verification** — ตรวจ module integrity

### ⚡ Performance
- **3 Performance Modes** — Light, Balanced, Paranoid
- **Auto Device Detection** — ปรับตามมือถือ/PC
- **Event Pooling** — ลด GC pressure
- **Adaptive Sampling** — ลด CPU เมื่อ idle
- **Bloom Filter Dedup** — ลด redundant events

---

## 🏗️ สถาปัตยกรรม
