# JSIntel Phase 1 Summary

- Total assets: 34
- JavaScript assets: 30
- Endpoints: 59
- Technologies: 4
- Security findings (low+): 76
- All findings: 23446 (critical 4, high 4, medium 63, low 5, info 23370)
- Fuzz probes: 0 (0 interesting)
- Web services: 7 (6 on non-standard ports)
- Screenshots: 7 (3 distinct visual clusters) — see reports/screenshots.html

## File statistics

- configuration: 2
- javascript: 30
- manifest: 1
- webassembly: 1

## Web services (port scan)

- http://api.vuln.lab:5001/ (200) [Werkzeug/2.2.3 Python/3.11.15]
- http://dvwa.vuln.lab:8081/ (200) — Login :: Damn Vulnerable Web Application (DVWA)
- http://goat.vuln.lab:8082/ (404)
- http://goat.vuln.lab:9090/ (404)
- http://graphql.vuln.lab:5013/ (200) — Damn Vulnerable GraphQL Application
- http://shop.vuln.lab:80/ (200) [SimpleHTTP/0.6 Python/3.14.7]
- http://shop.vuln.lab:3000/ (200) — OWASP Juice Shop
