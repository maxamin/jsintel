# JSIntel Phase 1 Summary

- Total assets: 31
- JavaScript assets: 27
- Endpoints: 59
- Technologies: 4
- Security findings (low+): 73
- All findings: 22474 (critical 4, high 4, medium 60, low 5, info 22401)
- Fuzz probes: 0 (0 interesting)
- Web services: 15 (12 on non-standard ports)

## File statistics

- configuration: 2
- javascript: 27
- manifest: 1
- webassembly: 1

## Web services (port scan)

- http://dvwa.vuln.lab:80/ (200) [SimpleHTTP/0.6 Python/3.14.7]
- http://dvwa.vuln.lab:3000/ (200) — OWASP Juice Shop
- http://dvwa.vuln.lab:8081/ (200) — Login :: Damn Vulnerable Web Application (DVWA)
- http://dvwa.vuln.lab:8082/ (404)
- http://dvwa.vuln.lab:9090/ (404)
- http://goat.vuln.lab:80/ (200) [SimpleHTTP/0.6 Python/3.14.7]
- http://goat.vuln.lab:3000/ (200) — OWASP Juice Shop
- http://goat.vuln.lab:8081/ (200) — Login :: Damn Vulnerable Web Application (DVWA)
- http://goat.vuln.lab:8082/ (404)
- http://goat.vuln.lab:9090/ (404)
- http://shop.vuln.lab:80/ (200) [SimpleHTTP/0.6 Python/3.14.7]
- http://shop.vuln.lab:3000/ (200) — OWASP Juice Shop
- http://shop.vuln.lab:8081/ (200) — Login :: Damn Vulnerable Web Application (DVWA)
- http://shop.vuln.lab:8082/ (404)
- http://shop.vuln.lab:9090/ (404)
