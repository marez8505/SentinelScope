# Install — Windows (WSL)

These instructions target Windows 10/11 with the Windows Subsystem for Linux
running an Ubuntu 22.04 (or later) distribution. WSL is Microsoft's
recommended path for Linux-style development on Windows
(see [Microsoft's WSL install guide](https://learn.microsoft.com/windows/wsl/install)).

> SentinelScope is an authorized-use tool. Before you install or run it,
> make sure every host you intend to scan is one you own or have explicit
> written permission to test.

## 1. Install WSL and Ubuntu

Open PowerShell as Administrator and run:

```powershell
wsl --install -d Ubuntu-22.04
```

Reboot if prompted, then launch **Ubuntu 22.04** from the Start menu and
finish the first-run setup (username, password).

## 2. Install Node.js 20

Inside the Ubuntu shell:

```bash
sudo apt update
sudo apt install -y curl build-essential git
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs
node --version    # should print v20.x
npm --version
```

The `build-essential` package is required because `better-sqlite3` builds a
native module on `npm install`. The NodeSource repository is the standard way
to get a current Node release on Debian/Ubuntu
(see [nodejs.org/distro](https://nodejs.org/en/download/package-manager)).

## 3. Get the SentinelScope source

```bash
cd ~
# from a tarball / archive you already have:
mkdir -p ~/code && cd ~/code
# (extract sentinelscope/ here, or git clone if you have it in a private repo)
cd sentinelscope
```

## 4. Install dependencies and build

```bash
npm install
npm run typecheck
npm test
npm run build
```

`npm test` runs the unit suite (target validation, port parsing, severity
prioritization, report rendering). All tests should pass before you run a real
scan.

## 5. Configure environment

```bash
cp .env.example .env
```

Open `.env` and optionally set:

- `PORT` — defaults to `5000`.
- `NVD_API_KEY` — optional NVD API key from
  [nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key).
  Without a key, NVD enforces a stricter rate limit (5 requests / 30s).

## 6. Run

```bash
npm start
```

Open <http://localhost:5000> in a Windows browser. WSL2 forwards the port to
Windows automatically.

## 7. Updating the local vulnerability snapshot

The first launch seeds a small bundled CVE/KEV/EPSS snapshot so the GUI is
useful immediately. To pull a fresh snapshot from the live feeds, open the
**Vulnerability Feed** page in the GUI and click **Refresh** on each card,
or call the API directly:

```bash
curl -X POST http://localhost:5000/api/feeds/nvd/refresh
curl -X POST http://localhost:5000/api/feeds/kev/refresh
curl -X POST http://localhost:5000/api/feeds/epss/refresh
```

Outbound network access is required for these calls (the feeds are hosted by
[NVD](https://services.nvd.nist.gov/rest/json/cves/2.0),
[CISA](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json),
and [FIRST](https://api.first.org/data/v1/epss)).

## Troubleshooting

- **`better-sqlite3` build failure** — make sure `build-essential` is installed
  and `node --version` reports v20+. Then `rm -rf node_modules && npm install`.
- **Cannot reach `localhost:5000` from Windows** — confirm the dev/prod server
  is bound to `0.0.0.0` (the template default) and that no Windows Defender
  Firewall rule is blocking WSL.
- **Slow filesystem on `/mnt/c/...`** — clone the project under your Linux home
  directory (`~/code/sentinelscope`), not on a mounted Windows drive.
