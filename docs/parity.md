# Nezha 1:1 Rust Parity Checklist

Target: the Rust implementation should match the visible Dashboard and Agent behavior of
`nezhahq/nezha` and `nezhahq/agent`, including API contracts, protocol messages,
authorization rules, runtime side effects, and operational entry points.

## Current Baseline

- Dashboard upstream: `nezhahq/nezha` `origin/master` at `636f4a971653ce3f5272fee99dc85c0bd5f923ef`
- Agent upstream: `nezhahq/agent` `origin/main` at `ba6f1a5f02b2cb645390a5f9dbd1f0f47479d07f`
- Proto contract: matched against both upstream proto files.
- Quantified parity: 103 / 103 audited behavior groups = 100.0%.
- Status: current audited behavior groups are at 100.0% parity against the pinned upstream
  Dashboard and Agent revisions.

## Progress By Area

- Protocol: 10 / 10 = 100.0%
- Dashboard API: 31 / 31 = 100.0%
- Dashboard runtime: 25 / 25 = 100.0%
- Agent tasks/runtime: 27 / 27 = 100.0%
- Security and permission regressions: 10 / 10 = 100.0%

## Recently Revalidated And Fixed

- Dashboard `GET /api/v1/service` now returns stored service monitor stats instead of a placeholder.
- Dashboard `GET /api/v1/service/server` now returns servers covered by service monitor config and
  applies upstream-style optional-auth visibility filtering.
- Dashboard `GET /api/v1/setting` now uses the upstream response shape:
  `config`, `version`, `frontend_templates`, and `tsdb_enabled`, with admin-only fields filtered.
- Dashboard frontend template metadata now comes from the vendored upstream
  `frontend-templates.yaml` catalog instead of a local two-entry placeholder, so admin settings
  expose the same template names, repositories, versions, and admin flags as upstream.
- Dashboard `GET /api/v1/setting` and frontend fallback now carry `user_template` and
  `admin_template` consistently, matching the upstream config surface more closely.
- Dashboard `/swagger` and `/swagger/{*path}` now serve a bundled Swagger UI and a generated
  `doc.json` derived from upstream swagger annotations at build time.
- Dashboard `ReportGeoIP` now performs local MaxMind country-code lookup before persisting and
  returning the gRPC response, instead of always returning an empty country code.
- Agent dashboard gRPC `insecure_tls` now actually skips certificate verification.
- Agent HTTP GET success data now follows upstream more closely: HTTPS success can report
  `issuer_common_name|not_after`, while plain HTTP success returns an empty data string.
- Agent host reporting now attempts to populate `virtualization` for common VM guests.
- Agent GeoIP reporting now caches the selected public IP, skips unchanged reports, retries after
  dashboard boot-time changes, and stores the dashboard-returned country code.
- Agent public IP discovery now uses separate IPv4 and IPv6 single-stack clients, with upstream DNS
  fallback lists and upstream-style short-circuiting when the network stack is unreachable.
- Agent virtualization reporting now follows upstream `gopsutil` behavior: Linux uses the same
  `/proc` and cgroup heuristics with guest-role filtering, while Windows and macOS return empty
  virtualization info just like upstream's not-implemented path.
- Agent self-update now uses the cached `cn` country code to choose Gitee/AtomGit mirrors when no
  explicit mirror flag is set, and uses an upstream-style temp stat file to avoid concurrent update
  races.
- Agent CLI now includes the upstream-style `edit` command to interactively update NIC, disk, DNS,
  UUID, GPU, temperature, and debug config fields and save them back to the selected config file.
- Dashboard `GET /api/v1/service` now includes dynamic cycle transfer stats for transfer-cycle alert
  rules and filters those stats by viewer-visible servers.
- Dashboard alert scheduling now maintains in-memory cycle-transfer sentinel state and serves
  `cycle_transfer_stats` from runtime state instead of reconstructing them on every HTTP request.
- Dashboard now provides a `sync-frontends` command that can build local `local:` frontend sources
  such as the self-hosted admin frontend and download release `dist.zip` files for remaining
  external templates into `static/*-dist`.
- Dashboard frontend fallback now matches the upstream deployment model more closely: once synced,
  the Rust binary embeds `static/*-dist` at build time and can still serve the official user/admin
  websites even when the external `static/` directory is missing at runtime.
- Dashboard WAF blocking now serves the upstream `waf.html` page content instead of a local
  placeholder HTML response, so blocked visitors see the same deployed page structure and copy.
- Dashboard Swagger UI is now gated behind `--debug` / `NZ_DEBUG`, matching the upstream
  debug-only exposure more closely instead of always serving `/swagger` in every runtime mode.
- Dashboard frontend fallback now also checks direct template paths before `static/`, so dropping a
  custom `user-dist` / `admin-dist` directory next to the process works more like the upstream
  local-file override behavior.

## Confirmed Parity Areas

- Protocol messages and gRPC method tags.
- Login, JWT issue/verify, bootstrap admin, roles, and permission filtering.
- Server stream visibility for guests, members, and admins.
- Service, alert, cron, notification, DDNS, NAT, WAF, user, profile, and group CRUD surfaces.
- Service scheduler, alert scheduler, cron scheduler, trigger task dispatch, and TSDB retention.
- Dashboard deployed frontend template catalog and release-asset synchronization.
- Dashboard deployed frontend packaging and runtime fallback from embedded frontend assets.
- Terminal, file manager, NAT, command, ICMP, TCP, config report/apply, and force update task paths.
- Agent operational entry points including service lifecycle control and interactive config editing.
- Notification template rendering and restricted outbound notification target checks.
- Agent GPU, temperature, TCP/UDP count, process count, and process group cleanup behavior.

## Verification Commands

Run these after each parity batch:

```powershell
cargo fmt --all -- --check
cargo check --workspace
cargo test --workspace
```

Manual runtime spot-check used for the latest frontend packaging parity confirmation:

```powershell
target\debug\nezha-dashboard.exe --client-secret secret --bind 127.0.0.1:5560 --http-bind 127.0.0.1:8012 --static-dir __missing_static_dir__
```

Confirmed against the running binary:

- `GET http://127.0.0.1:8012/` returned `200` and rendered the official user frontend.
- `GET http://127.0.0.1:8012/dashboard/login` returned `200` and rendered the official admin login frontend.
- Embedded assets such as `/dashboard/logo.svg`, `/dashboard/assets/index-*.js`, and `/assets/index.*.js`
  were served successfully without an external `static/` directory.
