# JSIntel Phase 1 Summary

- Total assets: 35
- JavaScript assets: 31
- Endpoints: 59
- Technologies: 4
- Security findings (low+): 101
- All findings: 23485 (critical 4, high 4, medium 71, low 22, info 23384)
- Fuzz probes: 0 (0 interesting)
- Web services: 7 (6 on non-standard ports)

## File statistics

- configuration: 2
- javascript: 31
- manifest: 1
- service: 7
- webassembly: 1

## Web services (port scan)

- http://api.vuln.lab:5001/ (200) [Werkzeug/2.2.3 Python/3.11.15]
- http://dvwa.vuln.lab:8081/ (200) — Login :: Damn Vulnerable Web Application (DVWA)
- http://goat.vuln.lab:8082/ (404)
- http://goat.vuln.lab:9090/ (404)
- http://graphql.vuln.lab:5013/ (200) — Damn Vulnerable GraphQL Application
- http://shop.vuln.lab:80/ (200) [SimpleHTTP/0.6 Python/3.14.7]
- http://shop.vuln.lab:3000/ (200) — OWASP Juice Shop
