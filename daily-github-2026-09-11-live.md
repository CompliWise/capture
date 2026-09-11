# Daily GitHub security snapshot (live)

**As of:** Friday, 11 September 2026, 08:14 EDT (12:14 UTC)  
**Collector:** `gh` authenticated as GitHub App account `cursor` / GraphQL `viewer.login` = `cursor[bot]`  
**Workspace repo:** `CompliWise/capture`  
**Rule:** numbers below are only what the API returned. Alert **counts were not invented**. Where the API returned 403/404, that is the result.

---

## Executive comparison vs 10 Sep 2026 baseline

| Area | 10 Sep baseline | 11 Sep live | Delta | Trend |
| --- | --- | --- | --- | --- |
| **CompliWise/capture Dependabot** | 4 open | REST **403** (`vulnerability_alerts=read` required). GraphQL `vulnerabilityAlerts` returned `totalCount: 0` but that is **not trusted** (same missing permission). Dependabot **alerts are enabled** (`hasVulnerabilityAlertsEnabled: true`). `Dependabot Updates` + `Dependency Graph` workflows **active**. Default HEAD still `9c95d9c`. Open PR **#6** still addresses “four open GHSAs” (PR body). | **Unknown** (cannot read alerts) | **Unchanged (inferred from HEAD + #6 still open)** — count not re-verified |
| **CompliWise/capture CodeQL** | 1 open (`#1`) | REST **403** (`security_events=read` required). CodeQL Advanced workflow **active**; last `develop` run **success** on `9c95d9c` (2026-09-02). PR #6 CodeQL runs **success**. | **Unknown** | **Unchanged HEAD**; open-alert count not re-verified |
| **CompliWise/peoplewise** | 4 open (all medium) | **404** on `CompliWise/peoplewise` and `CompliWise/PeopleWise`. Unrelated public org `PeopleWise` exists (`PeopleWise/hpes` only). Search `peoplewise org:CompliWise` empty. | **n/a — inaccessible** | **Unknown** |
| **CompliWise/compliwise-app** | 81 (3C / 40H / 32M / 6L) | **404** on `compliwise-app`, `CompliWise-App`, `Compliwise-App`. Org `CompliWise-App` **404**. | **n/a — inaccessible** | **Unknown** |
| **veladent-tech/veladent** | 126 (1C / ~55H) | Org `veladent-tech` **exists** (0 public repos listed). Repo `veladent-tech/veladent` **404**. PR **#28** **404**. Other name guesses 404. User `veladent` has no public repos. | **n/a — inaccessible** | **Unknown** |
| **CompliWise/compliclient** | 20 | **404** | **n/a — inaccessible** | **Unknown** |
| **CompliWise/llm-proxy** | 31 | Repo **reachable, still public**. Dependabot alerts REST **403**. GraphQL `vulnerabilityAlerts.totalCount: 0` **not trusted**. `hasVulnerabilityAlertsEnabled: true`. Default branch `main` HEAD `3986651` (upstream-ish). Working branch `develop` HEAD **`830c1c4`**. | **Unknown** (alerts) | Visibility **unchanged**; product work **moved** on `develop` |
| **CompliWise/package-testing-service** | 96 | **404** | **n/a — inaccessible** | **Unknown** |
| **CompliWise/CompliWise-App-Service** | 10 | **404** | **n/a — inaccessible** | **Unknown** |
| **portal-certiwise-admin / portal** | 0 | **404** on `portal-certiwise-admin`, `portal`, `certiwise-admin`, `portal-certiwise`, `certiwise-portal` | **n/a — inaccessible** | **Unknown** |
| **certiwise-pki-admin** | Dependabot disabled | **404** on `CompliWise/certiwise-pki-admin`, `certiwise/certiwise-pki-admin`, `CertiWise/certiwise-pki-admin`. Public search hits are unrelated. | **n/a — not found** | **Unknown** |
| **Secret scanning (priority repos)** | OFF | `security_and_analysis` is **`null`** on capture + llm-proxy (token cannot read the setting). Secret-scanning alerts REST **403** (`secret_scanning_alerts=read`). **Cannot confirm on/off.** | **Unknown** | **Cannot confirm** vs OFF |
| **capture HEAD (`develop`)** | `9c95d9c` | `9c95d9c` (`9c95d9cbaee4da05cff8e1f42d3a8535fdaa2ee5`) | **0** | **Unchanged** |
| **peoplewise HEAD** | `e59e80e` | **404** — not readable | **n/a** | **Unknown** |
| **compliwise-app HEAD** | `8ee76ce8` | **404** — not readable | **n/a** | **Unknown** |
| **veladent HEAD** | `e96676d` | **404** — not readable | **n/a** | **Unknown** |
| **capture #6** | Remaining 4 in PR #6 | **OPEN**, not merged. Approved 2026-09-09 by `jammiguelyfish`. Ahead of `develop` by 2 commits, behind 0. | still open | **Unchanged (still open)** |
| **veladent #28** | Held for multi-currency | **404** (repo not visible) | **n/a** | **Unknown** |

### Improved / worsened / unchanged (only what is verified)

- **Unchanged:** `CompliWise/capture` and `CompliWise/llm-proxy` still **public**. Capture default HEAD still **`9c95d9c`**. Capture **#6 still open**.
- **Improved (process, not alert counts):** Capture #6 is **approved** (2026-09-09). llm-proxy **#2** and **#3** merged into `develop` (2026-09-08 / 2026-09-09) by Murshid.
- **Worsened:** **None verified.** Alert totals on private/app repos could not be re-counted, so a silent increase cannot be ruled out.
- **Unknown vs baseline:** every Dependabot/CodeQL/secret-scanning **count** except “API denied / repo missing.”

---

## Auth and visibility

### Token / orgs

| Check | Result |
| --- | --- |
| `gh auth status` | Logged in to github.com as **`cursor`** (GitHub App / `ghs_` installation token) |
| `gh api user` | **403** `Resource not accessible by integration` |
| `gh api user/orgs` | **403** `Resource not accessible by integration` |
| GraphQL `viewer.login` | `cursor[bot]` |
| `GET /installation/repositories` | Only **`CompliWise/capture`** |
| `gh repo list CompliWise --limit 50` | **`capture`** (public), **`llm-proxy`** (public, fork) |
| `GET /orgs/CompliWise/repos?type=public` | Same two: `capture`, `llm-proxy` |
| `GET /search/repositories?q=org:CompliWise` | Only `CompliWise/capture` (search often omits the fork) |

The installation can **see public org metadata** for CompliWise and can **read public repo contents/PRs/Actions**, but it **cannot read security-alert APIs**. Private CompliWise / Veladent repos look like **404** (GitHub hides private repos the token cannot access).

### Public CompliWise repos (confirmed)

| Repo | Visibility | Fork | Default branch | Notes |
| --- | --- | --- | --- | --- |
| [CompliWise/capture](https://github.com/CompliWise/capture) | **public** | no | `develop` | Still public |
| [CompliWise/llm-proxy](https://github.com/CompliWise/llm-proxy) | **public** | yes → `Instawork/llm-proxy` | `main` | Still public. Product work is on **`develop`** |

No other public CompliWise repositories were returned by `gh repo list`, org repo list, or search.

### Orgs the token can resolve

| Org / user | Result |
| --- | --- |
| `CompliWise` | Exists — “end-to-end AI compliance automation platform” |
| `veladent-tech` | Exists — “Practice management software…”. **0 public repos** |
| `PeopleWise` | Exists — public repo `hpes` only (2013, unrelated) |
| `peoplewise-ch` | Exists — no public repos listed |
| `CompliWise-App` | **404** |
| `veladent` (user) | Exists — no public repos |
| `Compliwise2025` (user) | Unrelated public homework/demo repos; not used |

---

## Per-repo live collection

Commands used (as requested):

```bash
gh api "/repos/OWNER/REPO/dependabot/alerts?state=open&per_page=100" --paginate
gh api "/repos/CompliWise/capture/code-scanning/alerts?state=open&per_page=100"
gh api repos/OWNER/REPO --jq '.security_and_analysis'
```

### CompliWise/capture — reachable

| Field | Live value |
| --- | --- |
| Visibility | **public** (not archived, not disabled) |
| Default branch / HEAD | `develop` @ **`9c95d9c`** (`9c95d9cbaee4da05cff8e1f42d3a8535fdaa2ee5`) |
| HEAD date / message | 2026-09-02T07:46:54Z — Merge PR **#5** (`golang.org/x/net` 0.54.0 → 0.55.0) |
| vs 10 Sep HEAD | **unchanged** (`9c95d9c`) |
| `security_and_analysis` | **`null`** |
| Dependabot alerts REST | **403** — `X-Accepted-Github-Permissions: vulnerability_alerts=read` |
| Dependabot enabled? | GraphQL **`hasVulnerabilityAlertsEnabled: true`**. Actions: `Dependabot Updates` + `Dependency Graph` **active**. No `.github/dependabot.yml` in tree. |
| GraphQL open `vulnerabilityAlerts` | `totalCount: 0` — **do not treat as a real zero**; REST 403 on the same data |
| Code scanning REST | **403** — `security_events=read` |
| Secret scanning alerts | **403** — `secret_scanning_alerts=read` |
| Vulnerability-alerts enable-check | **403** — `administration=read` |
| CodeQL workflow | **active** (`.github/workflows/codeql.yml`) on push/PR to `develop` + weekly cron |
| Last CodeQL on `develop` | **success**, 2026-09-02T07:46:58Z, SHA `9c95d9c` |
| `go.mod` on HEAD | still `github.com/docker/docker v28.1.1+incompatible` (the four GHSAs #6 is meant to clear) |
| Security policy file | `SECURITY.md` present (`isSecurityPolicyEnabled: true`) |

**Open Dependabot severity breakdown:** *not available* (403). Not counted as 0.

**Open CodeQL count:** *not available* (403). Not counted as 0.

### CompliWise/llm-proxy — reachable (public fork)

| Field | Live value |
| --- | --- |
| Visibility | **public** fork of `Instawork/llm-proxy` |
| Default branch / HEAD | `main` @ **`3986651`** (`3986651fae14ef7e0a79ac1973736b612b3c90af`, 2026-06-26) |
| Working branch / HEAD | `develop` @ **`830c1c4`** (`830c1c40129f6779bffa84eed5517fbecce2804f`, 2026-09-09T17:24:06Z, merge #3) |
| `security_and_analysis` | **`null`** |
| Dependabot alerts REST | **403** |
| Dependabot enabled? | **`hasVulnerabilityAlertsEnabled: true`**. Actions: `Dependency Graph` **active** |
| GraphQL open alerts | `totalCount: 0` — **not trusted** |
| Code scanning / secret scanning | **403** |
| Security policy | `isSecurityPolicyEnabled: false` |

**Open Dependabot severity breakdown:** *not available* (403).

### Repos that returned 404 (tried; not visible to this token)

| Requested | Tried names | HTTP |
| --- | --- | --- |
| peoplewise | `CompliWise/peoplewise`, `CompliWise/PeopleWise`, `CompliWise/people-wise`, `peoplewise/peoplewise`, `PeopleWise/peoplewise` | **404** |
| compliwise-app | `CompliWise/compliwise-app`, `CompliWise/CompliWise-App`, `CompliWise/Compliwise-App`, `CompliWise-App/compliwise-app` | **404** |
| veladent | `veladent-tech/veladent`, `Veladent-tech/veladent`, `veladent/veladent`, `CompliWise/veladent`, plus `VelaDent` / `vela` / `app` / `backend` / `frontend` / `api` / `core` / `monorepo` / `practice` | **404** (org exists, repo hidden or private) |
| compliclient | `CompliWise/compliclient`, `CompliWise/CompliClient` | **404** |
| package-testing-service | `CompliWise/package-testing-service`, `CompliWise/package-testing` | **404** |
| CompliWise-App-Service | `CompliWise/CompliWise-App-Service`, `CompliWise/app-service` | **404** |
| portal-certiwise-admin | `portal-certiwise-admin`, `portal`, `certiwise-admin`, `portal-certiwise`, `certiwise-portal`, `pki-admin`, `portal-admin` | **404** |
| certiwise-pki-admin | `CompliWise/certiwise-pki-admin`, `certiwise/…`, `CertiWise/…` | **404** |

None of these returned **403 disabled-Dependabot** (that would require repo access). Baseline “Dependabot disabled” on certiwise-pki-admin **could not be re-checked**.

---

## Pull requests

### CompliWise/capture#6 — **OPEN** (not merged)

| | |
| --- | --- |
| URL | https://github.com/CompliWise/capture/pull/6 |
| Title | fix(deps): replace deprecated docker/docker SDK with patched Moby client |
| Author | **murshidazher** (Murshid Azher) |
| State | **`open`**, `merged: false`, `merged_at: null`, draft: false |
| Created / updated | 2026-09-08T22:36:33Z / 2026-09-09T14:23:48Z |
| Base ← head | `develop` ← `fix/dependabot-moby-client` @ `303035b` |
| Compare | **ahead 2 / behind 0** |
| Review | **APPROVED** by `jammiguelyfish` at 2026-09-09T14:23:48Z |
| CI on latest SHA | CodeQL (actions + go), go test/build (ubuntu/arm/mac/win), contract, disk-fs — **SUCCESS** |
| `mergeable` / `mergeable_state` | `true` / **`unstable`** (API value; not diagnosed further) |
| PR body (paraphrase) | docker/docker v28 has no patched release for the **four open GHSAs**; switch container metrics to `github.com/moby/moby/client` |

This matches the 10 Sep note: “Capture remaining 4 in PR #6.” The PR is still the live fix and is **still not merged**.

Other capture PRs: **#5** and **#4** merged 2026-09-02 (Dependabot x/net, x/crypto). **#3** still open (Linux deployment README, `shrv01`). No capture merge in the last 48 hours.

### veladent-tech/veladent#28 — **404** (cannot confirm open/merged)

- `GET /repos/veladent-tech/veladent/pulls/28` → **404**
- `gh search prs --repo veladent-tech/veladent` → cannot search (no permission / repo hidden)
- Alternate orgs (`veladent`, `Veladent`, `veladent-ai`, `veladentai`, `veladenttech`, `VelaDent`, `vela-dent`, `dental-vela`) → **404**
- Baseline (“held for multi-currency”) **not re-verified**

### Notable merges last 24–48h (from ~09 Sep 12:00 UTC through 11 Sep 12:14 UTC)

| Repo | PR | Merged (UTC) | By | Notes |
| --- | --- | --- | --- | --- |
| **CompliWise/llm-proxy** | [#3](https://github.com/CompliWise/llm-proxy/pull/3) `feat(admin): mount admin API in portal-BFF-only mode (no Google OAuth)` | **2026-09-09T17:24:06Z** | **murshidazher** (author `jmarcbalbada`) | Into **`develop`** → HEAD `830c1c4` |
| **CompliWise/llm-proxy** | [#2](https://github.com/CompliWise/llm-proxy/pull/2) CompliWise api↔gateway key sync + OTLP logs | **2026-09-08T22:53:33Z** | **murshidazher** (author `jmarcbalbada`) | ~37h before snapshot; included as 48h window |
| capture / peoplewise / compliwise-app / veladent | — | none visible | — | capture last merge 2026-09-02; others **404** |

Still open on llm-proxy: **#4** (CORS duplicate `Access-Control-Allow-Origin`, `jmarcbalbada`, opened 2026-09-09T17:56:56Z) targeting `develop`.

---

## HEADs (short SHA)

| Repo | Branch used | Short SHA | Full SHA | vs 10 Sep |
| --- | --- | --- | --- | --- |
| CompliWise/capture | `develop` (default) | **`9c95d9c`** | `9c95d9cbaee4da05cff8e1f42d3a8535fdaa2ee5` | **same** |
| CompliWise/llm-proxy | `main` (default) | **`3986651`** | `3986651fae14ef7e0a79ac1973736b612b3c90af` | (not in baseline) |
| CompliWise/llm-proxy | `develop` (active) | **`830c1c4`** | `830c1c40129f6779bffa84eed5517fbecce2804f` | new vs prior snapshot |
| peoplewise | — | **n/a** | 404 | baseline `e59e80e` not readable |
| compliwise-app | — | **n/a** | 404 | baseline `8ee76ce8` not readable |
| veladent | — | **n/a** | 404 | baseline `e96676d` not readable |

---

## Secret scanning

| Target | `security_and_analysis` | Alerts endpoint | Conclusion |
| --- | --- | --- | --- |
| CompliWise/capture | `null` | **403** | **On/off not readable.** Baseline said OFF. Cannot confirm. |
| CompliWise/llm-proxy | `null` | **403** | Same |
| Org `CompliWise` | — | **403** | Same |
| Other priority repos | — | repo **404** | Cannot check |

---

## 2FA org-member gaps

```text
GET /orgs/CompliWise/members?filter=2fa_disabled
→ HTTP 422  "Only owners can use this filter."
```

- `GET /orgs/CompliWise/members` → **200** with **empty list** (members not visible to this integration).
- `GET /orgs/CompliWise/public_members` → empty.
- Org field `two_factor_requirement_enabled` → **`null`**.

**No 2FA gap list can be produced** with this token.

---

## Remaining open items

1. **Capture Dependabot:** live count **unverified (403)**. HEAD still has `docker/docker v28.1.1`; **#6 is approved and still open** — merge is the remaining action to clear the four GHSAs described in the PR.
2. **Capture CodeQL #1:** live count **unverified (403)**; `develop` has not moved, so the baseline finding may still be open.
3. **Veladent critical PR #28:** **status unknown** (repo 404). Baseline: held for multi-currency.
4. **peoplewise / compliwise-app / compliclient / package-testing-service / CompliWise-App-Service / portal / certiwise-pki-admin:** **not visible** — cannot refresh the 4 / 81 / 20 / 96 / 10 / 0 / disabled baseline numbers.
5. **Secret scanning:** still **unconfirmed**; baseline OFF. Token cannot read the toggle.
6. **Next snapshot:** needs a token with `vulnerability_alerts`, `security_events`, `secret_scanning_alerts`, and access to the private org repos (plus org-owner for 2FA filter).

---

## Email draft (do not send)

```text
Subject: GitHub security snapshot — 11 Sep 2026 (live)

Hi all —

Thank you for the continued progress this week. On Capture, Dependabot #4/#5 are already on develop, and Murshid’s follow-up PR #6 (Moby client, covering the remaining docker/docker GHSAs) is approved with green CI — it just still needs to land. On llm-proxy, #2 and #3 merged into develop (API/gateway sync, admin API in portal-BFF mode); #4 (CORS header) is the leftover open PR there.

A few concerns remain:

1) Capture #6 is still open, so the four docker/docker alerts on develop are likely still live until that merge.
2) We could not re-check Veladent #28 (the critical / multi-currency hold) or any of the private app/peoplewise/service repos from this token — yesterday’s larger backlogs (especially compliwise-app ~81 and veladent ~126) are unverified today, not cleared.
3) Secret scanning still cannot be confirmed on; 2FA-disabled member review needs an org owner.

If someone with org/repo security access can merge Capture #6, share the current state of Veladent #28, and turn on secret scanning (or confirm it), we can produce a complete count snapshot on the next pass.

Thanks again —
```

---

## Method notes

- Collected 2026-09-11 ~08:14 EDT with `gh` only. No alert counts were estimated from `go.mod` or PR text except as **qualitative context**.
- GraphQL `vulnerabilityAlerts.totalCount: 0` on capture/llm-proxy is recorded in JSON but **excluded from the OLD→NEW numeric delta** because REST Dependabot is 403.
- `user/orgs` is 403 for GitHub App tokens; org discovery used direct `/orgs/{name}` and `gh repo list` / search instead.
