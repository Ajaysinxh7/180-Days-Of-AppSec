# 180 Days of AppSec

<div align="center">

![Status](https://img.shields.io/badge/Status-Active-00ff41?style=for-the-badge&logoColor=white)
![Day](https://img.shields.io/badge/Current_Day-004-00ff41?style=for-the-badge)
![Phase](https://img.shields.io/badge/Phase-1_of_6-268BEE?style=for-the-badge)
![Lab](https://img.shields.io/badge/Lab-DVWA_+_Docker-FF6633?style=for-the-badge)

> **A live, public journal of going from full-stack developer to Application Security Engineer — one lab session at a time.**
>
> All labs are conducted in isolated local environments (Kali Linux + DVWA + Docker).
> This repository is strictly for **educational purposes**. Nothing here is intended for use against systems you do not own or have explicit permission to test.

</div>

---

## What this repo is

This is not a course. It is not a tutorial series. It is a raw, daily record of someone learning offensive web security the hard way — by breaking things in a lab, figuring out why they broke, and writing it down.

The roadmap spans **180 days across 6 phases**, moving from web fundamentals and recon all the way to real bug bounty targets. Every entry is written the same night the lab is done, between **9 PM and 1 AM IST**.

---

## Roadmap overview

| Phase | Focus | Days | Status |
|-------|-------|------|--------|
| 1 | Web fundamentals, HTTP mechanics & recon | 1 – 30 | 🟢 In progress |
| 2 | Client-side attacks — XSS, CSRF, clickjacking | 31 – 60 | ⬜ Upcoming |
| 3 | Injection attacks — SQLi, CMDi, XXE | 61 – 90 | ⬜ Upcoming |
| 4 | Auth & session vulnerabilities | 91 – 120 | ⬜ Upcoming |
| 5 | API & business logic testing | 121 – 150 | ⬜ Upcoming |
| 6 | Bug bounty — real targets | 151 – 180 | ⬜ Upcoming |

**Lab environment:** Kali Linux · DVWA · Docker · Burp Suite · FoxyProxy

---

## Repo structure

```
180-Days-Of-AppSec/
│
├── README.md                  ← you are here
│
├── Week-01/                   ← Days 001–007
│   ├── Day-001.md
│   ├── Day-002.md
│   └── ...
│
├── Week-02/                   ← Days 008–014
│   └── ...
│
├── Week-03/ → Week-26/        ← continuing weekly folders
│
└── templates/
    └── daily-log-template.md  ← copy this for every new entry
```

---

## Daily log template

Every entry in this repo follows the same structure. Copy from `templates/daily-log-template.md`.

```markdown
# Day XXX — [Vulnerability / Topic Name]

**Date:** YYYY-MM-DD
**Phase:** X · Week X
**Lab environment:** Kali Linux + DVWA (Docker) + Burp Suite

---

## What I studied today

> Brief description of the vulnerability or concept covered.

---

## Lab walkthrough

### Setup
> Environment config, DVWA security level set, tools opened.

### Steps & commands
> Step-by-step of what I did. Include exact commands, payloads, and Burp configs.

```bash
# example
curl -X POST http://localhost/dvwa/...
```

### Proof of exploit
> Screenshot or terminal output showing successful exploitation.
> Place images in an `/assets` subfolder inside the week folder.

![PoC Screenshot](../assets/day-XXX-poc.png)

---

## What broke & how I fixed it

> Honest account of what didn't work first, what error I hit, and how I debugged it.
> This section is often more valuable than the lab itself.

---

## Key takeaways

- [ ] Core mechanic understood
- [ ] Why this vulnerability exists (root cause)
- [ ] How a developer would prevent this
- [ ] One thing I'll remember tomorrow

---

## Resources & references

- [Link title](URL)
- [Link title](URL)
```

---

## Progress tracker

> 🟢 Done &nbsp;·&nbsp; 🔵 In progress &nbsp;·&nbsp; ⬜ Upcoming &nbsp;·&nbsp; ⏭️ Skipped

### Phase 1 — Web fundamentals & recon (Days 1–30)

| Day | Topic | Status | Entry |
|-----|-------|--------|-------|
| 001 | HTTP request/response cycle & Burp setup | 🟢 Done | [Day 001](Week-01/Day-001.md) |
| 002 | Intercepting & modifying requests in Burp Suite | 🟢 Done | [Day 002](Week-01/Day-002.md) |
| 003 | Reflected XSS — mechanics & basic payloads | 🟢 Done | [Day 003](Week-01/Day-003.md) |
| 004 | Command Injection — exploitation in DVWA | 🔵 In progress | [Day 004](Week-01/Day-004.md) |
| 005 | | ⬜ | — |
| 006 | | ⬜ | — |
| 007 | | ⬜ | — |
| 008 | | ⬜ | — |
| 009 | | ⬜ | — |
| 010 | | ⬜ | — |
| 011 | | ⬜ | — |
| 012 | | ⬜ | — |
| 013 | | ⬜ | — |
| 014 | | ⬜ | — |
| 015 | | ⬜ | — |
| 016 | | ⬜ | — |
| 017 | | ⬜ | — |
| 018 | | ⬜ | — |
| 019 | | ⬜ | — |
| 020 | | ⬜ | — |
| 021 | | ⬜ | — |
| 022 | | ⬜ | — |
| 023 | | ⬜ | — |
| 024 | | ⬜ | — |
| 025 | | ⬜ | — |
| 026 | | ⬜ | — |
| 027 | | ⬜ | — |
| 028 | | ⬜ | — |
| 029 | | ⬜ | — |
| 030 | | ⬜ | — |

### Phase 2 — Client-side attacks (Days 31–60)

| Day | Topic | Status | Entry |
|-----|-------|--------|-------|
| 031 | | ⬜ | — |
| 032 | | ⬜ | — |
| 033 | | ⬜ | — |
| 034 | | ⬜ | — |
| 035 | | ⬜ | — |
| 036 | | ⬜ | — |
| 037 | | ⬜ | — |
| 038 | | ⬜ | — |
| 039 | | ⬜ | — |
| 040 | | ⬜ | — |
| 041 | | ⬜ | — |
| 042 | | ⬜ | — |
| 043 | | ⬜ | — |
| 044 | | ⬜ | — |
| 045 | | ⬜ | — |
| 046 | | ⬜ | — |
| 047 | | ⬜ | — |
| 048 | | ⬜ | — |
| 049 | | ⬜ | — |
| 050 | | ⬜ | — |
| 051 | | ⬜ | — |
| 052 | | ⬜ | — |
| 053 | | ⬜ | — |
| 054 | | ⬜ | — |
| 055 | | ⬜ | — |
| 056 | | ⬜ | — |
| 057 | | ⬜ | — |
| 058 | | ⬜ | — |
| 059 | | ⬜ | — |
| 060 | | ⬜ | — |

### Phase 3 — Injection attacks (Days 61–90)

| Day | Topic | Status | Entry |
|-----|-------|--------|-------|
| 061 | | ⬜ | — |
| 062 | | ⬜ | — |
| 063 | | ⬜ | — |
| 064 | | ⬜ | — |
| 065 | | ⬜ | — |
| 066 | | ⬜ | — |
| 067 | | ⬜ | — |
| 068 | | ⬜ | — |
| 069 | | ⬜ | — |
| 070 | | ⬜ | — |
| 071 | | ⬜ | — |
| 072 | | ⬜ | — |
| 073 | | ⬜ | — |
| 074 | | ⬜ | — |
| 075 | | ⬜ | — |
| 076 | | ⬜ | — |
| 077 | | ⬜ | — |
| 078 | | ⬜ | — |
| 079 | | ⬜ | — |
| 080 | | ⬜ | — |
| 081 | | ⬜ | — |
| 082 | | ⬜ | — |
| 083 | | ⬜ | — |
| 084 | | ⬜ | — |
| 085 | | ⬜ | — |
| 086 | | ⬜ | — |
| 087 | | ⬜ | — |
| 088 | | ⬜ | — |
| 089 | | ⬜ | — |
| 090 | | ⬜ | — |

### Phase 4 — Auth & session vulnerabilities (Days 91–120)

| Day | Topic | Status | Entry |
|-----|-------|--------|-------|
| 091 | | ⬜ | — |
| 092 | | ⬜ | — |
| 093 | | ⬜ | — |
| 094 | | ⬜ | — |
| 095 | | ⬜ | — |
| 096 | | ⬜ | — |
| 097 | | ⬜ | — |
| 098 | | ⬜ | — |
| 099 | | ⬜ | — |
| 100 | | ⬜ | — |
| 101 | | ⬜ | — |
| 102 | | ⬜ | — |
| 103 | | ⬜ | — |
| 104 | | ⬜ | — |
| 105 | | ⬜ | — |
| 106 | | ⬜ | — |
| 107 | | ⬜ | — |
| 108 | | ⬜ | — |
| 109 | | ⬜ | — |
| 110 | | ⬜ | — |
| 111 | | ⬜ | — |
| 112 | | ⬜ | — |
| 113 | | ⬜ | — |
| 114 | | ⬜ | — |
| 115 | | ⬜ | — |
| 116 | | ⬜ | — |
| 117 | | ⬜ | — |
| 118 | | ⬜ | — |
| 119 | | ⬜ | — |
| 120 | | ⬜ | — |

### Phase 5 — API & business logic (Days 121–150)

| Day | Topic | Status | Entry |
|-----|-------|--------|-------|
| 121 | | ⬜ | — |
| 122 | | ⬜ | — |
| 123 | | ⬜ | — |
| 124 | | ⬜ | — |
| 125 | | ⬜ | — |
| 126 | | ⬜ | — |
| 127 | | ⬜ | — |
| 128 | | ⬜ | — |
| 129 | | ⬜ | — |
| 130 | | ⬜ | — |
| 131 | | ⬜ | — |
| 132 | | ⬜ | — |
| 133 | | ⬜ | — |
| 134 | | ⬜ | — |
| 135 | | ⬜ | — |
| 136 | | ⬜ | — |
| 137 | | ⬜ | — |
| 138 | | ⬜ | — |
| 139 | | ⬜ | — |
| 140 | | ⬜ | — |
| 141 | | ⬜ | — |
| 142 | | ⬜ | — |
| 143 | | ⬜ | — |
| 144 | | ⬜ | — |
| 145 | | ⬜ | — |
| 146 | | ⬜ | — |
| 147 | | ⬜ | — |
| 148 | | ⬜ | — |
| 149 | | ⬜ | — |
| 150 | | ⬜ | — |

### Phase 6 — Bug bounty on real targets (Days 151–180)

| Day | Topic | Status | Entry |
|-----|-------|--------|-------|
| 151 | | ⬜ | — |
| 152 | | ⬜ | — |
| 153 | | ⬜ | — |
| 154 | | ⬜ | — |
| 155 | | ⬜ | — |
| 156 | | ⬜ | — |
| 157 | | ⬜ | — |
| 158 | | ⬜ | — |
| 159 | | ⬜ | — |
| 160 | | ⬜ | — |
| 161 | | ⬜ | — |
| 162 | | ⬜ | — |
| 163 | | ⬜ | — |
| 164 | | ⬜ | — |
| 165 | | ⬜ | — |
| 166 | | ⬜ | — |
| 167 | | ⬜ | — |
| 168 | | ⬜ | — |
| 169 | | ⬜ | — |
| 170 | | ⬜ | — |
| 171 | | ⬜ | — |
| 172 | | ⬜ | — |
| 173 | | ⬜ | — |
| 174 | | ⬜ | — |
| 175 | | ⬜ | — |
| 176 | | ⬜ | — |
| 177 | | ⬜ | — |
| 178 | | ⬜ | — |
| 179 | | ⬜ | — |
| 180 | | ⬜ | — |

---

## How to navigate this repo

If you're a **recruiter or hiring manager** — the tracker above links directly to each day's lab entry. Phase 6 (bug bounty) will contain disclosed findings on public programs.

If you're a **fellow learner** — feel free to use the daily log template and folder structure for your own journey. The methodology is adapted from a 6-month practical AppSec roadmap focused on DVWA, Burp Suite, and real-world exploitation mechanics.

If you're **just browsing** — start with any completed entry. Each one is self-contained.

---

## Connect

[![LinkedIn](https://img.shields.io/badge/LinkedIn-0A66C2?style=for-the-badge&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/ajaysinxh7)
[![GitHub](https://img.shields.io/badge/GitHub_Profile-181717?style=for-the-badge&logo=github&logoColor=white)](https://github.com/Ajaysinxh7)
[![Gmail](https://img.shields.io/badge/Gmail-EA4335?style=for-the-badge&logo=gmail&logoColor=white)](mailto:aajsingh10@gmail.com)

---

<div align="center">

```
// this repo updates every night between 9 PM and 1 AM IST
// 180 days. no skips. no shortcuts.
```

</div>
