# JSIntel vulnerable-target lab

A repeatable, **local** estate of intentionally-vulnerable web apps for authorized
regression and stress testing of JSIntel. It gives the pipeline a realistic
multi-host target: a `/etc/hosts` subdomain tree, several application stacks, and
web services on **non-standard ports** (not just 80/443).

> ⚠️ **Everything here is deliberately vulnerable and is bound to loopback only.**
> The harness binds every service to a `127.0.0.0/8` address and runs an
> `assert_loopback` gate after each start that **kills** any service found bound to
> `0.0.0.0`, `*`, or a routable address. Never expose these apps off the host.

## The estate

Each app gets its own loopback IP (127.0.0.0/8 is all loopback on Linux), so a
port scan of one host sees only that host's real services — a genuine subdomain
tree, not one shared address.

| Host (`/etc/hosts`)  | IP          | App                         | Stack         | Port(s)     |
|----------------------|-------------|-----------------------------|---------------|-------------|
| `shop.vuln.lab`      | 127.0.0.1   | OWASP Juice Shop            | Node          | 3000        |
| `goat.vuln.lab`      | 127.0.0.2   | OWASP WebGoat + WebWolf     | Java (Spring) | 8082, 9090  |
| `dvwa.vuln.lab`      | 127.0.0.3   | DVWA                        | PHP + MariaDB | 8081        |
| `api.vuln.lab`       | 127.0.0.4   | VAmPI (REST/JWT)            | Python/Flask  | 5001        |
| `graphql.vuln.lab`   | 127.0.0.5   | Damn Vulnerable GraphQL App | Python/Flask  | 5013        |

All five apps deploy on this host. VAmPI and DVGA can't build against the host
Python 3.14, so the harness runs them from **their Docker image's own Python** via
`docker export` + a loopback chroot (`targets/rootfs.sh`) — Docker is used for
dependency compatibility, not for container networking. The first `up` of either
exports the image filesystem into `runtime/<app>-rootfs/` (needs the Docker daemon;
`lab.sh` starts one automatically in vfs/no-bridge mode).

## Usage

```bash
tests/lab/lab.sh up [id...]        # provision + start all apps (or named ids)
tests/lab/lab.sh down [id...]      # stop all (or named)
tests/lab/lab.sh status            # running state + health per app
sudo tests/lab/lab.sh hosts install  # add the subdomain tree to /etc/hosts
sudo tests/lab/lab.sh hosts remove   # remove it again
tests/lab/lab.sh seeds             # print seed URLs (feed to jsintel -i)
tests/lab/lab.sh scope             # print comma-joined scope (feed to -s/-p/-f)
```

App ids: `juice vampi dvga webgoat dvwa`. Provisioning is idempotent — the first
`up` downloads/clones each app into `runtime/`; later runs reuse it.

### Point JSIntel at the lab

```bash
sudo tests/lab/lab.sh hosts install
tests/lab/lab.sh up juice webgoat dvwa
tests/lab/lab.sh seeds > tests/lab/seeds_up.txt

JSINTEL_PORTS="80,443,3000,5001,5013,8081,8082,9090" \
  ./jsintel.sh -i tests/lab/seeds_up.txt -o output_lab_full \
    -p shop.vuln.lab,goat.vuln.lab,dvwa.vuln.lab -w -t 20
```

Then read `output_lab_full/reports/triage.md` (or `triage.html`). A correct run
ranks `shop.vuln.lab` **critical** with the Juice Shop sensitive endpoints and
eval/taint/secret findings.

## Layout

```
tests/lab/
├── lab.sh                 # controller (up/down/status/hosts/seeds/scope)
├── manifest.json          # declarative estate description
├── targets/
│   ├── loopback-shim.js   # forces any Node server onto its LAB_BIND_IP
│   └── dvwa-db.sh         # repo-local, loopback-only MariaDB for DVWA
└── runtime/               # downloaded apps, pidfiles, logs, DB data (git-ignored)
```

## Host prerequisites

- `node`, `java`, `php` + `php-mysql` (mysqli), `python3`+venv, `git`, `curl`.
- **MariaDB (for DVWA):** the datadir lives under the repo, outside the path the
  MariaDB AppArmor profile allows, so the harness relaxes it to complain mode
  (`aa-complain /usr/sbin/mariadbd`, best-effort). Install `apparmor-utils` if
  `aa-complain` is missing.

## Docker usage (and why not full containers)

This sandbox's kernel cannot create the `docker0` bridge (`operation not
supported`), and Docker's only reachable mode here (`--network host`) binds
`0.0.0.0`, which is unsafe for vulnerable apps. So containers are **not** run as
network services. Docker is still used two ways:

- Apps that run natively (Juice Shop, WebGoat, DVWA) bind an explicit `127.x`
  address directly.
- Apps whose dependencies don't build on the host Python (VAmPI, DVGA) are run
  from **their image's own interpreter**: `docker export` the image filesystem,
  then `chroot` + bind loopback (`targets/rootfs.sh`). Docker gives dependency
  compatibility; the loopback bind gives safety.

The `docker_image` field in `manifest.json` records each app's canonical image so
a real Docker/Compose host can swap it back in. See `TESTING_PROGRESS.md` for
detail.

## Running the estate on a real Docker host

This sandbox can't bridge-network containers, so the multi-service / CMS apps
(bWAPP, Mutillidae, NodeGoat, RailsGoat, crAPI) can't run here. On any normal
Docker host, `tests/lab/docker-compose.yml` brings up the whole estate — including
those — each on a distinct non-standard localhost port:

```bash
tests/lab/lab-docker.sh up              # docker compose up -d + health-check
sudo tests/lab/lab-docker.sh hosts install   # map the subdomain tree -> 127.0.0.1
tests/lab/lab-docker.sh seeds > seeds.txt     # feed to jsintel -i
./jsintel.sh -i seeds.txt -p "$(tests/lab/lab-docker.sh scope)" -w
tests/lab/lab-docker.sh status          # container state + per-host health
tests/lab/lab-docker.sh down
```

`lab-docker.sh` wraps `docker-compose.yml` with the same UX as the native `lab.sh`
(up/down/status/hosts/seeds/scope) and includes the CMS/multi-service apps that
can't run in the sandbox (bWAPP, Mutillidae, WordPress, NodeGoat, RailsGoat). crAPI
ships its own large compose (see the note at the bottom of `docker-compose.yml`).
