<div align="center">

# 180 Days of AppSec

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=14&pause=1000&color=00FF41&background=00000000&center=true&vCenter=true&width=600&lines=Breaking+web+apps+legally%2C+one+lab+at+a+time.;6+phases.+180+days.+No+shortcuts.;DVWA+%2B+Burp+Suite+%2B+Kali+Linux.;Daily+logs+from+9+PM+to+1+AM+IST." alt="Typing SVG" />

<br>

![Status](https://img.shields.io/badge/Status-Active-00ff41?style=flat-square)
![Current Day](https://img.shields.io/badge/Day-015%20of%20180-00ff41?style=flat-square)
![Current Phase](https://img.shields.io/badge/Phase-1%20%E2%80%94%20Web%20Fundamentals-268BEE?style=flat-square)
![Lab](https://img.shields.io/badge/Lab-DVWA%20%2B%20Docker-FF6633?style=flat-square)
![OS](https://img.shields.io/badge/OS-Kali%20Linux-268BEE?style=flat-square&logo=kalilinux&logoColor=white)

</div>

---

> All labs are conducted in isolated local environments.
> This repository exists strictly for **educational purposes** — nothing documented here is intended for use against systems you don't own or have explicit written permission to test.

---

## What this is

A raw, daily record of going from full-stack developer to Application Security Engineer. Every entry is written the same night the lab is done — no polishing after the fact, no skipping the parts that didn't work.

The roadmap runs **180 days across 6 phases**, from HTTP mechanics and recon all the way to hunting on real bug bounty programs. Each week lives in its own folder. Each day gets its own file.

---

## Lab environment

| Tool | Purpose |
|------|---------|
| **Kali Linux** | Primary attack OS |
| **DVWA** | Vulnerable web app target |
| **Docker** | Isolated lab container |
| **Burp Suite** | Traffic interception & manipulation |
| **FoxyProxy** | Browser proxy routing |
| **VMware** | Virtualization layer |

---

## Roadmap

```
┌─────────────────────────────────────────────────────────────────┐
│                    6-PHASE APPSEC ROADMAP                       │
├──────────┬──────────────────────────────────────┬───────────────┤
│ Phase 1  │ Web Fundamentals & Recon             │ Days 001–030  │
│          │ HTTP, Burp setup, headers, recon     │ 🟢 ACTIVE     │
├──────────┼──────────────────────────────────────┼───────────────┤
│ Phase 2  │ Client-Side Attacks                  │ Days 031–060  │
│          │ XSS, CSRF, Clickjacking              │ ⬜ UPCOMING   │
├──────────┼──────────────────────────────────────┼───────────────┤
│ Phase 3  │ Injection Attacks                    │ Days 061–090  │
│          │ SQLi, Command Injection, XXE         │ ⬜ UPCOMING   │
├──────────┼──────────────────────────────────────┼───────────────┤
│ Phase 4  │ Auth & Session Vulnerabilities       │ Days 091–120  │
│          │ Broken auth, session hijacking       │ ⬜ UPCOMING   │
├──────────┼──────────────────────────────────────┼───────────────┤
│ Phase 5  │ API & Business Logic Testing         │ Days 121–150  │
│          │ REST/GraphQL, logic flaws            │ ⬜ UPCOMING   │
├──────────┼──────────────────────────────────────┼───────────────┤
│ Phase 6  │ Bug Bounty — Real Targets            │ Days 151–180  │
│          │ HackerOne / Bugcrowd live programs   │ ⬜ UPCOMING   │
└──────────┴──────────────────────────────────────┴───────────────┘
```

---

## Repo structure

```
180-Days-Of-AppSec/
│
├── README.md
│
├── Week-01/                  ← Days 001–007
│   ├── assets/               ← screenshots & PoC images for this week
│   ├── Day-001.md
│   ├── Day-002.md
│   └── ...
│
├── Week-02/                  ← Days 008–014
├── Week-03/
│   ...
├── Week-26/                  ← Days 176–180
│
└── templates/
    └── daily-log-template.md
```

---

## What each daily log contains

Every entry follows the same structure:

```
# Day XXX — [Vulnerability / Topic]

1. What I studied today     → concept + root cause
2. Lab walkthrough          → setup, steps, exact commands & payloads
3. Proof of exploit         → screenshot or terminal output
4. What broke & how I fixed → honest debugging notes
5. Key takeaways            → mechanic, root cause, developer fix
6. Resources & references   → links used
```

Copy the template from [`templates/daily-log-template.md`](templates/daily-log-template.md) for every new entry.

---

## How to navigate

**Recruiter / hiring manager** — browse completed week folders. Phase 6 will contain disclosed bug bounty findings from public programs.

**Fellow learner** — the folder structure and daily template are free to copy for your own journey. The methodology is built around hands-on exploitation in controlled lab environments before touching any real target.

**Just browsing** — each daily entry is self-contained. Start anywhere.

---

## Connect

<div align="center">

[![LinkedIn](https://img.shields.io/badge/LinkedIn-0A66C2?style=for-the-badge&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/ajaysinxh7)
[![GitHub](https://img.shields.io/badge/Profile-181717?style=for-the-badge&logo=github&logoColor=white)](https://github.com/Ajaysinxh7)
[![Gmail](https://img.shields.io/badge/Gmail-EA4335?style=for-the-badge&logo=gmail&logoColor=white)](mailto:aajsingh10@gmail.com)

</div>

---

<div align="center">

```
// updated nightly · 9 PM – 1 AM IST
```

</div>
