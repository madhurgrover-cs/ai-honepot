
# 🛡️ AI Web Honeypot (LLM‑Powered Deception System)

An **AI‑driven web honeypot** that simulates a vulnerable web application in real time using a **local LLM**.  
Instead of blocking attackers, it **engages, deceives, and profiles them**—while exposing **zero real attack surface**.

Built for a cybersecurity hackathon.

---

## 🚀 What Makes This Different?

Traditional honeypots return static responses.  
This system **improvises realistic backend behavior** using an LLM.

**Key features:**
- 🧠 AI‑generated fake server responses
- 🌐 Vulnerable‑looking web endpoints
- 🐚 Fake web shell (no real execution)
- 📊 Attack logging & behavior analysis
- 🔒 Fully local (no cloud, no API keys)
- ⚡ GPU‑accelerated LLM support

---

## 🏗️ Architecture

Attacker (Browser / curl / Burp)
↓
Fake Web App (FastAPI)
↓
Request Analyzer (SQLi / XSS / RCE detection)
↓
LLM Deception Engine (Local via Ollama)
↓
Fake Response + Attack Logger


---

## 👥 Team Responsibilities

| Member | Responsibility |
|-----|---------------|
| **LLM Engineer** | Prompts, local LLM, deception realism |
| **Web Engineer** | Routes, logging, dashboards |



