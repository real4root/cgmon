# Changelog

All notable changes to cgmon. Versions are numbered `major.minor.patch`; every
build that reaches a router or a release gets a new patch number.

## 2.7.17

### Fixed
- Commands with more than 64 KB of output (`apk list -I` on routers with many packages,
  large `uci show`) waited for the timeout and returned nothing: the output is now read
  while the command runs (capped at 16 MB). Affects the package inventory of the
  vulnerability scanner and every other place that runs a command.
- Camera cloud check read the whole conntrack table into memory once per camera (tens of
  MB on a busy router): it is now streamed line by line once per check.

## 2.7.16

### Changed
- Phone layout of the page header: the title and a shorter «OpenWrt Settings» button share
  one line, the four chart/language selectors fit in the second line (was four lines).

## 2.7.15

### Changed
- The link to LuCI is now a prominent blue «OpenWrt Settings (LuCI)» button right after the
  «cgmon 2.7.x» title instead of a small «⚙ OpenWrt» among the chart controls.

## 2.7.14

### Added
- **«Update all» button** in the Security section header: all packages with an available
  update in one go. System packages (kernel and kmod-*, base-files, netifd, firewall,
  procd, dnsmasq, busybox, apk/opkg, hostapd…) are left out — they are safer to update with
  a firmware upgrade or one by one (their own buttons stay).

### Fixed
- **Free space is checked before any package update.** cgmon works out what will be
  installed together with dependencies (`apk add --simulate`), their installed sizes from
  the repository and how much the old versions free up — only if they live in the overlay:
  a package from the firmware (/rom) frees nothing, its new version lands in the overlay in
  full. Plus room for the largest package while its files are replaced and a 10 % / 1 MB
  margin. Not enough — the update is refused with the numbers and nothing is touched.

## 2.7.13

### Changed
- Security section: a click on a table row no longer opens a small card with the same text
  *and* the report window — it opens only the «Full report» window, scrolled to that
  package with its vulnerabilities expanded and highlighted.
- Less empty space between the section header and the table.

## 2.7.12

### Fixed
- Buttons in the «Full report» window («Update», «Isolate»): the password was asked on the
  main page behind the report window, and the confirmation then popped up in the report
  window — nothing seemed to happen. Now the confirmation comes first and the password is
  asked in the same window where the button was pressed; a correct password is remembered
  until the page is closed.

## 2.7.11

### Fixed
- curl: fresh CVEs whose OSV record has no upstream link yet stayed «unfixed» after an
  update (17 of 39 after 2.7.10). curl's own records (`CURL-CVE-…`) are now looked up
  directly, so each CVE is either dropped for the installed version or shows the real
  fixed version.

## 2.7.10

### Added
- **OpenWrt integration** (Settings → «cgmon settings: data and integration»):
  - «Router address opens»: LuCI (as before) or cgmon — `integration.home`. cgmon writes
    `/www/index.html`, keeps the previous one as `/www/index.html.cgmon-orig` and puts it
    back when LuCI is chosen again;
  - «router names for cgmon» — `integration.names`, e.g. `router.lan`, `cgmon.lan`: dnsmasq
    answers them with the router address in the network the question came from
    (`interface-name`), and these names always open cgmon, even with LuCI as the start page;
  - an «⚙ OpenWrt» link in the page header opens LuCI.
- The «cgmon data» card is renamed to «cgmon settings: data and integration».

### Fixed
- After updating a package whose vulnerabilities Debian has not assessed yet (curl 8.22.0
  kept all 39), nothing changed: for CVEs without a Debian fix the scanner now checks the
  upstream data in OSV — the project's own record (e.g. `CURL-CVE-…` with exact ranges per
  release branch) or the CPE version ranges of the CVE record. Not affected → dropped;
  affected → the real fixed version is shown.
- Security section on phones: the table no longer slides sideways — the «Issue» header is
  hidden together with its column, «Exploit probability» becomes «%», the
  «open to the internet» badge shrinks to 🌐, buttons wrap, the check line wraps.

## 2.7.9

### Changed
- Security tables show the installed version next to each package (main table and full
  report); the full report column is «Now → fixed in».

## 2.7.8

### Added
- **Cameras and recorders: is it in the vendor cloud?** For every detected camera/DVR the
  scanner checks whether it reaches the internet — answered connections right now
  (conntrack, unanswered attempts of an isolated device do not count) or more than 1 MB
  over 24 h by cgmon accounting. In the cloud (P2P, cloud ID) it can be reached from
  outside without any port forward: its XMEye / open RTSP / telnet findings go one step
  up and the camera itself becomes «medium» with the destinations and daily volume.
  Not reaching the internet — its findings drop to «low». Rows show «☁ uses the cloud» /
  «does not reach the internet».

### Changed
- The «Severity» column is now «Risk».
- A package row shows the exploit probability of the vulnerability that sets its risk, not
  the highest one among all of them (OpenSSH showed 24.9 % from a CVE Debian rates
  «unimportant», next to the risk «medium»). In the full report such CVEs get a ⓘ hint.

### Fixed
- «In OpenSSH 7.9, …»-style descriptions (one affected version) are recognised: such old
  CVEs no longer show for a newer version.

## 2.7.7

### Fixed
- Version comparison treated `10.6_p1` as older than `10.6` (a letter suffix was taken for
  a pre-release); now only rc/alpha/beta/pre/dev are pre-releases, `p1`, `k`… are newer.
- Descriptions with the last affected version («through 8.3p1», «4.6 and earlier», «up to
  X») are honoured: old CVEs that Debian keeps open no longer show for a newer version.

## 2.7.6

### Fixed
- A saved report from an earlier version kept old results until the next check (e.g.
  OpenSSH 10.6 still listed with «OpenSSH before 10.4»): the saved report is now brought
  to the current rules on start — fixed versions from descriptions, LAN severity scale.

## 2.7.5

### Changed
- Security section: the severity counters (serious / medium / …) moved into the header
  line next to «Check: … · kernel …»; the «Exploit probability» header fits on one line.
- LAN device findings: attackable only from your own network → at most «medium»
  (telnet, XMEye, camera video without a password), the rest «low»; a port forwarded
  from the internet raises it by two steps, up to «critical».
- The «Isolate» / «Lift isolation» buttons explain on hover what isolation does and why.
- «Check now» shows «⏳ checking…» while a check runs instead of silently ignoring clicks.

### Fixed
- After «Update» a package kept showing its vulnerabilities and the update button until the
  next weekly check: its findings are now recalculated for the new version at once, and a
  full re-check starts right after (also in «button only» mode).
- Vulnerabilities that Debian has not fixed yet stayed «unfixed» forever even on a newer
  upstream version: the fixed version is now taken from the description («OpenSSH before
  10.4», «prior to version …») when Debian gives none.

## 2.7.4

### Added
- **Device isolation from the internet.** The scanner detects cameras and video
  recorders (RTSP 554, XMEye 34567, Dahua 37777, Hikvision SDK 8000 or a camera vendor
  by MAC); they — and any LAN device with a serious finding — get an «Isolate» button.
  An isolated device keeps access to the local network and the router only; all its
  traffic to the internet is dropped before routing by its MAC (a new IP does not
  help, replies through port forwards stop too). «Lift isolation» undoes it; the list
  is the `vuln_scan.isolate` setting (also editable in «All settings»). Own nft table
  `inet cgmon_iso`, the firewall is not touched; works with the scanner off.
- «Current events» shows how many devices are isolated.

### Changed
- **Security section is compact**: a table of up to 8 rows (severity · what · issue ·
  exploit probability · button); «Full report» opens a separate window with tabs and,
  per package, every vulnerability (severity, exploit probability, CVSS, attack vector,
  fixed version, description).
- **One package — one row**: all vulnerabilities of a package are grouped together
  instead of a row per CVE.
- **Exploit probability (FIRST EPSS, %)** is a column of its own.
- **«Critical» only for what is reachable from the internet**: cgmon maps listening
  sockets to processes and packages and checks the wan firewall rules and port
  forwards. A vulnerability is critical only if the service is open to the internet,
  exploitable over the network and exploited/likely/CVSS ≥ 9. Anything attackable only
  from the LAN or the router itself (client libraries, local services) is at most
  «serious». The kernel handles all WAN traffic, so its network vulnerabilities count
  as reachable. A LAN device becomes critical only if a port is forwarded to it.
  Findings reachable from outside are marked «🌐 open to the internet · port N».

## 2.7.3

### Added
- **Vulnerability scanner** (new «🛡 Security» section; Settings → Security:
  off / button only / weekly, plus «check LAN devices»). One background check:
  - every installed package (by its source package and upstream version) and programs
    running outside packages (Go programs such as AdGuard Home and tailscale by their
    own version) against OSV.dev; Debian records add the Debian assessment (urgency,
    network vs local), CISA KEV marks exploited ones, FIRST EPSS gives the exploit
    probability; versions are compared upstream-to-upstream, so Debian epochs and
    revisions do not cause false alarms;
  - the kernel: thousands of Debian records are filtered by KEV/EPSS first, details are
    fetched only for exploited or likely ones, the rest is one summary line;
  - OpenWrt and LuCI own packages (uhttpd, odhcpd, procd, ubus, cgi-io…) against the
    OpenWrt GitHub security advisories (by release branch or package build date);
  - router settings: open WAN ports, port forwards, wan zone policies, root password,
    SSH password login, telnet, LuCI over http, Wi-Fi (open/WEP/WPA1/TKIP, WPS, short
    key), UPnP;
  - LAN devices (LAN interfaces only, safe probes, no login attempts): telnet, FTP,
    SMB, RDP, VNC, RTSP video without a password, XMEye/Dahua/Hikvision services,
    web interfaces over http.
  - Severity: «critical» only for exploited (KEV) or EPSS ≥ 10 %; a high CVSS alone is
    at most «serious»; local-only and Debian-«unimportant» issues are «low».
- **Update buttons** on findings: packages are upgraded with apk/opkg when the index has
  a newer version; cgmon updates itself from the latest release the way it is
  installed (package or binary), verifying SHA256 before replacing; the kernel gets a
  firmware (sysupgrade) hint.
- `cgmon vuln-scan` runs the check from the console and prints the report.

## 2.7.2

### Fixed
- The daemon language follows the page: with `lang: auto` (the default) the page sets
  its own language on first open, and changing the language on the page switches the
  journal, events and Telegram right away — no password needed (the language is not a
  secret; isolated subnets cannot change it). Previously the journal stayed in English
  until the password was entered.
- Setting hints come in the language of the page that asks for them, not the daemon's.
- Per-Site Routing: RIPEstat downloads are retried (3 attempts), the HTTP code is
  logged, a failed AS is retried after 10 minutes instead of an hour.

## 2.7.1

### Fixed
- Per-Site Routing: AS prefixes from RIPEstat were never loaded — the 100+ KB answer
  filled the pipe and curl blocked until the timeout («RIPEstat did not answer»).
  Now downloaded to a temporary file.

## 2.7.0

### Added
- **Full localization: English, Russian, Uzbek, Kazakh, Chinese.** Everything the
  daemon writes — journal, current events, incidents, Telegram messages, errors,
  CLI help and the setup wizard — now follows the `lang:` setting
  (`auto | en | ru | uz | kk | zh`; `auto` takes the LuCI language, otherwise
  English). Changing the language on the page also switches the daemon (when
  settings may be changed). `CGMON_LANG` overrides it for the console.
  Catalogs live in `i18n/*.tsv` (embedded in the binary compressed; only the active
  language is unpacked); `tools/i18n.py check` lists missing translations, tests
  check placeholders and message prefixes in every language.
- The page is fully translated into Uzbek, Kazakh and Chinese (previously about half
  of the strings fell back to English); setting hints of «All settings» and of the
  wizard come in the selected language instead of the Russian config comments.
- **Per-Site Routing — permanent list** (`dns_guard.persite`, `persite_file`,
  `persite_aaaa`). Moves hand-written PBR scripts into cgmon: sites (with
  subdomains), IPv4/IPv6 networks and whole AS (prefixes from RIPEstat, refreshed
  weekly, cached) always go through the chosen gate — «auto» uses the dynamic
  Per-Site Routing gate or the first working reroute path. Domain addresses are put
  into the set by dnsmasq (`nftset`) before the client gets the answer, with a
  fallback to DNS answers seen on the wire; listed IPv6 is refused so clients use
  IPv4 via the gate; AAAA of listed domains can be answered with `::`. Own nft table
  `inet cgmon_persite`. If the gate goes down, the sites go direct.
- The list is edited in a separate window (`persite.html`, «List…» button in
  Settings → Per-Site Routing): one entry per line or separated with `;`, comments
  after `#`, buttons to reformat, sort and dedupe; unrecognized entries are shown.
- «Current events» shows the permanent list and its gate.
- `CHANGELOG.md` (this file) and README in Uzbek, Kazakh and Chinese.

- **Config files in any encoding**: `cgmon.yaml` and the Per-Site Routing list are read
  as UTF-8 (with or without BOM), UTF-16 (Notepad «Unicode») or Windows «ANSI»
  (cp1251 Cyrillic / cp1252 Latin, detected automatically), with CRLF line endings.
  A file that was not UTF-8 is rewritten as UTF-8 in place; the original is kept as
  `<file>.orig-<encoding>`. No more «stream did not contain valid UTF-8» after
  editing in WinSCP/Notepad.

### Changed
- «Per-Site VPN» is renamed to **Per-Site Routing** everywhere (events, settings,
  journal).
- Down detector messages separate the service name with a colon
  («Telegram: not responding over IPv4…»), so the page groups them in any language.

### Fixed
- The WAN speed tile and the chart were capped at 120 Mbps by a leftover page
  setting (`max-speed-mbps`); the cap is removed (0 = none).
- TOP CPU / TOP RAM: a long process name (e.g. `napi/mtk_eth-6…`) no longer hides
  its percentage — only the name is shortened.
- Russian text leaking into other languages: backend messages, «All settings» group
  names, the empty device table and setting hints.

### Removed
- The duplicate «Per-Site Routing check: nodes … go via …» line in «Current events»
  (the check sites are already listed in the Per-Site Routing line).

## 2.6.x

- 2.6.30 — first public release of the 2.6 branch; private examples removed from
  hints and comments.
- 2.6.28 — Per-Site Routing catches «silent» ClientHello drops (no RST) on actively
  used sites.
- 2.6.19 — gateway drag-and-drop fixes, fast overlay fallback
  (`dns_guard.overlay_fail_sec`).
- 2.6.8 — a tunnel can carry all LAN traffic (overlay gateway) without touching the
  main route; automatic fallback to the physical link.
- 2.6.0 — gateway discovery core: gateway kinds (ZeroTier, Tailscale, WireGuard,
  AmneziaWG, L2TP, IPsec, OpenVPN, PPP, relay) and friendly names on the page.

## 2.5.x

- 2.5.0 — Per-Site Routing (then «Per-Site VPN»): sites whose TLS the ISP resets by
  name are caught in real traffic, confirmed by a direct probe and routed via the
  chosen gate.

## 2.4.x

- 2.4.21 — English docs by default, 7 architectures, UPX for lite/nano, apk/ipk
  packages.
- 2.4.8 — chart history on the router, `storage:` setting, page embedded in the
  binary.
- 2.4.0 — several gateways: gateway maps, two ISPs, ZeroTier/Tailscale gateways,
  physical-layer port watch.

## 2.3.x

- 2.3.39 — first Rust release (2.x); same config, page, CGI and hub format as Go
  1.3.38.

## 1.x

- Go versions: 1.1 — netlink accounting; 1.2 — multi-router hub with encrypted
  reports and Telegram, setup wizard, live config; 1.3 — DNS guard, down detector,
  per-site metrics.
