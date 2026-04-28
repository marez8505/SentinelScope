# Install — Windows (PowerShell, native)

These instructions install SentinelScope directly on Windows using PowerShell,
without WSL. The WSL guide
([INSTALL-WSL.md](INSTALL-WSL.md)) is generally smoother — use this one only
if you specifically need a native Windows environment.

> SentinelScope is an authorized-use tool. Make sure every host you intend
> to scan is one you own or have explicit written permission to test.

## 1. Install Node.js 20

The simplest path is to install Node from
[nodejs.org/download](https://nodejs.org/en/download) — pick the LTS
Windows installer (`.msi`).

If you use [winget](https://learn.microsoft.com/windows/package-manager/),
open PowerShell and run:

```powershell
winget install OpenJS.NodeJS.LTS
```

Close and reopen PowerShell, then verify:

```powershell
node --version    # v20.x.x
npm --version
```

## 2. Install Git and Visual C++ Build Tools

`better-sqlite3` builds a native binding on install. Windows needs the MSVC
build tools.

```powershell
winget install Git.Git
winget install Microsoft.VisualStudio.2022.BuildTools --override "--quiet --wait --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"
```

Reopen PowerShell after this so the new tools are on `PATH`.

## 3. Get the SentinelScope source

```powershell
cd $HOME
mkdir code -ErrorAction SilentlyContinue | Out-Null
cd code
# Extract the sentinelscope archive here, then:
cd sentinelscope
```

## 4. Install, typecheck, test, build

```powershell
npm install
npm run typecheck
npm test
npm run build
```

If the install fails on `better-sqlite3`, ensure the VC build tools from
step 2 are installed and visible (`where.exe cl.exe` should resolve), then
delete `node_modules` and re-run `npm install`.

## 5. Configure environment

```powershell
Copy-Item .env.example .env
notepad .env
```

Optional values:

- `PORT` — defaults to `5000`.
- `NVD_API_KEY` — optional key from
  [nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key).

## 6. Run

```powershell
npm start
```

Then open <http://localhost:5000>.

## 7. Refreshing the local CVE / KEV / EPSS snapshot

Use the **Vulnerability Feed** page in the GUI and click **Refresh** on each
card. Or, from PowerShell:

```powershell
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:5000/api/feeds/refresh `
  -ContentType 'application/json' -Body '{"source":"nvd"}'
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:5000/api/feeds/refresh `
  -ContentType 'application/json' -Body '{"source":"kev"}'
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:5000/api/feeds/refresh `
  -ContentType 'application/json' -Body '{"source":"epss"}'
# Or refresh all three at once:
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:5000/api/feeds/refresh `
  -ContentType 'application/json' -Body '{"source":"all"}'
```

Outbound network access is required to reach
[NVD](https://services.nvd.nist.gov/rest/json/cves/2.0),
[CISA KEV](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json),
and [FIRST EPSS](https://api.first.org/data/v1/epss).

## Troubleshooting

- **`gyp ERR! find VS`** — the VC build tools from step 2 are missing or not on
  PATH. Restart PowerShell, or run `npm config set msvs_version 2022`.
- **`EACCES` / `EPERM`** — avoid running the install from a path with
  OneDrive-controlled folders (e.g., `Documents`); prefer `%USERPROFILE%\code\`.
- **Antivirus / EDR blocking outbound TCP** — SentinelScope only opens TCP
  connections to the targets you scan. If your endpoint security is blocking
  outbound traffic, scoping it to the local app process is the right fix.
