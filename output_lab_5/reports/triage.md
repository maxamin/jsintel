# JSIntel Triage — hosts that matter, ranked

- Hosts ranked: 5
- Hosts with a critical/high finding: 1

| Rank | Host | Risk | Max sev | Findings | Sensitive eps | Services |
|---:|---|---:|---|---|---:|---:|
| 1 | shop.vuln.lab | 1224 | critical | critical 4, high 4, medium 60, low 5 | 15 | 2 |
| 2 | graphql.vuln.lab | 37 | medium | medium 3 | 0 | 1 |
| 3 | goat.vuln.lab | 10 | none | — | 0 | 2 |
| 4 | api.vuln.lab | 7 | none | — | 0 | 1 |
| 5 | dvwa.vuln.lab | 7 | none | — | 0 | 1 |

## shop.vuln.lab — risk 1224 (critical)

- Score: findings 1175 + endpoints 40 + exposure 9
- Services:
  - http://shop.vuln.lab:80/ (200)
  - http://shop.vuln.lab:3000/ (200) — OWASP Juice Shop ⚠ non-standard port
- Top findings:
  - [critical] dangerous_eval: `Func...3286 (len 21)`
  - [critical] dangerous_eval: `Func...6552 (len 21)`
  - [critical] dangerous_eval: `eval...ne 2 (len 14)`
  - [critical] taint_to_sink: `loca...ne 2 (len 29)`
  - [high] hardcoded_secret: `aws-...ureL (len 34)`
  - [high] hardcoded_secret: `goog....com (len 35)`
  - [high] taint_to_sink: `loca...1068 (len 46)`
  - [high] taint_to_sink: `loca...1069 (len 46)`
  - [medium] prototype_pollution: `dyna...ne 1 (len 35)`
  - [medium] prototype_pollution: `dyna...ne 1 (len 35)`
- Sensitive endpoints: `/api/Challenges/?key=nftMintChallenge`, `/api/Users`, `/api/v1/users`, `/api/v2/register`, `/rest/2fa/disable`, `/rest/2fa/setup`, `/rest/2fa/status`, `/rest/2fa/verify`, `/rest/admin`, `/rest/admin/application-configuration`, `/rest/saveLoginIp`, `/rest/user/authentication-details/`, `/rest/user/change-password?current=`, `/rest/user/login`, `/rest/user/reset-password`

## graphql.vuln.lab — risk 37 (medium)

- Score: findings 30 + endpoints 0 + exposure 7
- Services:
  - http://graphql.vuln.lab:5013/ (200) — Damn Vulnerable GraphQL Application ⚠ non-standard port
- Top findings:
  - [medium] prototype_pollution: `dyna...ne 6 (len 35)`
  - [medium] prototype_pollution: `dyna...ne 1 (len 35)`
  - [medium] prototype_pollution: `dyna...ne 2 (len 35)`

## goat.vuln.lab — risk 10 (none)

- Score: findings 0 + endpoints 0 + exposure 10
- Services:
  - http://goat.vuln.lab:8082/ (404) ⚠ non-standard port
  - http://goat.vuln.lab:9090/ (404) ⚠ non-standard port

## api.vuln.lab — risk 7 (none)

- Score: findings 0 + endpoints 0 + exposure 7
- Services:
  - http://api.vuln.lab:5001/ (200) ⚠ non-standard port

## dvwa.vuln.lab — risk 7 (none)

- Score: findings 0 + endpoints 0 + exposure 7
- Services:
  - http://dvwa.vuln.lab:8081/ (200) — Login :: Damn Vulnerable Web Application (DVWA) ⚠ non-standard port

