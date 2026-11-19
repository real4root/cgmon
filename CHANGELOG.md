# Changelog

All notable changes to cgmon. Versions are numbered `major.minor.patch`; every
build that reaches a router or a release gets a new patch number.

## 2.8.6

### Changed
- Collection hub: the provider and each hub status are one line ("provider: X · address ·
  N sent · M s ago").
- Settings: the option labels of "Threat lists" ("small (~2k)" …) and "Package sources"
  ("no", "stable only", "stable + beta for serious") are back as in 2.8.4. In 2.8.5 they were
  shortened without need.

### Security
- Botnet watch:
  - **List caps:** if a source suddenly grows or is replaced, the lists are cut at
    400k domains / 100k addresses (full), 60k / 15k (lite) or 8k / 3k (nano).
  - **Finding cap:** at most 500 findings are kept; the oldest by last time is dropped.
  - **Event rate:** events are limited per device and threat kind — at most one every
    10 minutes, even when a device hits many domains from a list. All findings are still
    counted.
- Code review of the changes since 2.7.17: page input and the data from devices, DNS and
  threat lists. The page escapes all of it on output. uci, nft and apk get their arguments
  directly, without a shell. The device name, MAC, IP, knock steps, forwards and interfaces
  are checked both on the page and in the daemon. Feed addresses are built from constants.

## 2.8.5

### Changed
- Settings page:
  - "Threat lists" no longer has a "by build" option. With `auto` the list shows the size
    that applies to this build (full — "large"); the setting changes only when another size is
    chosen.
  - "Fixes from the main OpenWrt repository" is now "Package sources" and is the first row of
    the Security card. The values are short ("firmware", "+ OpenWrt", "+ OpenWrt beta");
    details are in the "?".
  - The "Knock steps" field takes the free width of the row.
  - Port-knocking → forwards: the label and the fields line up with the other labels.
    "No forwards" is shown in the label row; the list appears only when there are forwards.
  - "Where to keep intermediate data": the "now: /etc/cgmon/" line moved into the tooltip.
    A separate line appears only on an error.
  - Collection hub: each hub status is one line ("address · N sent · M s ago", ending in
    "…" if it does not fit). The label is shortened to "This router is the hub".

## 2.8.4

### Added
- Naming a device from the page. Next to the device name in "Active devices" there is a ✎
  (it shows on hover).
  - The name (Latin letters, digits and "-") is saved as a DHCP static lease (`config host`:
    name, MAC, IP, dns) and as a router hostname (`config domain`: name → IP) in
    `/etc/config/dhcp`, then dnsmasq re-reads its settings.
  - The name shows in cgmon, in LuCI and in DNS (`name.lan`), even for a device with a
    manual address that does not report its name (for example Windows in a public network).
  - An empty name removes both records. The settings password is required.
  - From the console: `cgmon dev-name MAC IP [NAME]`.

### Changed
- The "botnet watch" line moved to the bottom of the Security block, right of the "Full
  report" button, aligned right. In the full report window it stays in the header.

### Fixed
- Vulnerability scan: Docker 29 and newer (dockerd 29.6.1 on a test router) got false high findings,
  for example CVE-2026-34040. Since version 29 Docker lives in the Go module
  `github.com/moby/moby/v2`; the old `github.com/docker/docker` is frozen at 28, and OSV
  says "everything is affected, no fix" for it. Now the version is mapped from the Docker tag
  through the Go module proxy (`docker-v29.6.1` → `v2.0.0-beta.18…`), and OSV is queried
  for `moby/moby/v2`. If the proxy is unavailable, the old behaviour is kept.

## 2.8.3

### Changed
- The Security header now has two lines: the vulnerability check on top, and the botnet watch
  below it in smaller text. The severity chips no longer wrap one by one; on phones they
  wrap as a group.

### Fixed
- Port-knocking card: on a narrow column the "+" button of the forwards stuck out past the
  card edge. The fields and the button are now a flexible row.

## 2.8.2

### Changed
- Botnet watch findings no longer repeat the device name in the issue text; it is already
  in the "What" column.

### Checked
- Live test on a test router (x86_64, ImmortalWrt 25.12), from a LAN machine:
  - a DNS query for a C2IntelFeeds domain → "Botnet: … command server";
  - 30 random non-existent names → "Suspicious: … domain generation";
  - a connection to an address from Spamhaus DROP → the kernel recorded the pair in `hits4` →
    "Threat: … (Spamhaus DROP)";
  - SYN to 40 documentation addresses (203.0.113.0/24) on port 23 → "Botnet: … scans the
    internet".
- With the large lists (190k domains, 36k IPs, 1.7k networks) cgmon on the test router uses 9.3 MB RSS
  (12.3 MB peak while loading). nft parses the 580 KB address script in 0.5 s.

## 2.8.1

### Fixed
- Botnet watch: the address table was not created, because the chain name `fwd` is an nft
  keyword. Chains are now `fw_hits` and `out_hits`. After an nft error, cgmon re-applies the
  table at most once an hour instead of every minute (the script for 36k addresses is
  580 KB).

## 2.8.0

### Added
- Botnet and threat watch (`threat_watch:`, module `src/threatwatch.rs`). cgmon watches every
  device on the network: a TV box, a camera, a computer or a vacuum cleaner can all be part
  of a botnet.
  - **Threat lists**, downloaded daily in the background, no keys needed:
    - command servers: C2IntelFeeds (domains and IPs), Feodo Tracker, SSLBL;
    - malware distribution: URLhaus, mirrored by malware-filter (the abuse.ch exports now
      require a key);
    - Spamhaus DROP;
    - HaGeZi TIF: 190k domains and 36k IPs.
  - **List size** depends on the build: `lists: auto` gives full — large (~230k entries,
    ~2 MB RAM, ~4 MB traffic a day), lite — medium (~20k, ~0.2 MB), nano — small (command
    servers and live URLhaus hosts, ~2k).
  - **Domains:** DNS answers to devices are checked against the lists (a domain and its
    parent domains). Domains are stored as 64-bit hashes in a sorted array, 8 bytes per domain; a
    check is a few hashes and a binary search.
  - **Addresses:** kept in the nft sets `inet cgmon_threat` (single IPs in a hash set,
    networks in an interval set). The kernel itself records "device . address" pairs for
    new connections from the LAN and from the router; cgmon collects them once a minute.
  - **Behavior, without lists:**
    - Internet scanning: ≥30 addresses in SYN_SENT on one port among
      telnet/SSH/ADB/TR-069/SMB/RDP/VNC/databases in two snapshots in a row — worms like
      Mirai.
    - Random non-existent domains: ≥25 in an hour (domain generation, DGA).
    - ≥600 addresses at once for 10 minutes: a proxy botnet, or torrents, so it is only
      "suspicious".
  - **Findings** appear in Security as LAN device rows with the Isolate button, and in the
    events (no more often than every 6 hours per device and threat). They are kept for 7 days
    and saved to `/etc/cgmon/threat.json`.
  - The Security header shows how many domains and addresses are being watched.
  - Settings, in the Security card: "Botnet watch" (on/off), "Threat lists" (by build,
    small, medium or large) and "Behavior signs".

## 2.7.41

### Fixed
- Gateways and address bypass: tunnels without their own default route never appeared among
  the paths. Examples: OpenVPN with `redirect-gateway def1` (routes 0.0.0.0/1 + 128.0.0.0/1),
  OpenVPN with `route-nopull`, WireGuard without `route_allowed_ips`. Now every
  point-to-point tunnel that is up and has IPv4 (OpenVPN tun, WireGuard, AmneziaWG, L2TP,
  GRE, IPsec, a backup PPPoE…) is a path: cgmon puts `default dev <tunnel>` into its own
  table, no gateway address is needed. On the page such tunnels can also be the "all
  traffic" gateway (overlay).
  - Tailscale is a path only when an exit node is selected: then Tailscale puts a default
    route into table 52 itself. Without an exit node tailscaled drops internet traffic.
  - ZeroTier and other L2 networks work through an `@name` node: they need a gateway
    address.

## 2.7.40

### Changed
- The knock card is now "🚪 Port-knocking", and its row is "Interfaces".
  - The button has a fixed width and shows only "on" or "off"; the interface list opens on
    click.
  - The top item of the list is "Disable" while something is selected and "off" otherwise.
    Checking any interface turns it back into "Disable".
  - The gateways group is titled "gateways — enable the ones you need".

### Fixed
- Settings: the "?" icon sat below the middle of the line in every row (by 1.9 px) and in
  card headers (by 1.1 px), for example "Speed: queue and upload". It was aligned to
  lowercase letters (`vertical-align: middle`). Now the line height of labels, headers and
  subheaders is fixed, and the icon is placed at the exact center (checked in headless Chrome:
  0 px offset in all 64 rows and all headers).

## 2.7.39

### Fixed
- Port knocking: the old `knock.from` value `wan4`/`wan6` also expanded to netifd interface
  names that are not devices (INTERNET, @INTERNET, INTERNET_6). Only real devices are used
  now.

## 2.7.38

### Changed
- Port knocking: interfaces are chosen per device. The candidates are every device with a
  route to the internet (`default` in any routing table: WAN, modem, OpenVPN `tun*`,
  WireGuard…) and every VPN network (ZeroTier, Tailscale, `wg*`, `tun*`, `tap*`, IPsec, GRE…),
  shown under their netifd names. Old `knock.from` values still work: `wan4`/`wan6` mean all
  WAN devices, `zerotier`/`tailscale` mean all such devices.
- Knock steps can be ping, TCP or UDP in any mix: `knock.steps: ["ping:100", "tcp:7000",
  "udp:8123"]`. The old `knock.sizes` (ping only) is read as before. Only knock-like packets
  enter the knock chain, so ordinary traffic from the same address does not break the
  sequence.
- The knock card is compact. The "Knock" row is a dropdown: "off" plus interfaces with
  checkboxes, grouped into "gateways" and "VPN networks". The CGNAT note and the commands moved
  to a "how to knock" window, which puts the router address into the commands (chosen from the
  addresses of the selected interfaces, or `%address`). Commands are given for
  Linux/Android/macOS and Windows PowerShell, including TCP and UDP steps.

## 2.7.37

### Fixed
- Port knocking: the remaining access time was read wrong ("9m58s440ms" — milliseconds were
  taken as minutes, so the event said "for 570 min" instead of 10).
- Port knocking: "external IPv4" in the card showed the address of a backup modem behind the
  router (192.168.2.2) instead of PPPoE. Addresses outside home networks now come first.

## 2.7.36

### Added
- Port knocking in cgmon (`knock:`, card "🚪 Port knocking" in the 3rd settings column).
  - **The knock:** access opens for the address that sent pings of the given sizes in order,
    one packet each (default `ping -s 100`, `100`, `122`). No client app is needed.
  - **What opens:** the router ports (default 22 and 80) are redirected to the router LAN
    address, so SSH that listens on LAN only becomes reachable from WAN and via
    ZeroTier/Tailscale. Forwards ("ports=address[:port]") lead to LAN devices. Access lasts
    `open_min` minutes; a wrong ping size resets the sequence.
  - **Where knocks are accepted:** checkboxes for internet IPv4, internet IPv6, ZeroTier and
    Tailscale. If the external IPv4 is behind CGNAT, the card warns that knocks over IPv4
    from the internet cannot arrive, and shows the current external IPv6.
  - **How it is built:** a `inet cgmon_knock` table, plus "marked by knock — accept" rules in
    fw4 input/forward. fw4 loses them on a firewall reload; cgmon restores them within 30 s.
  - **In the card:** ready-made commands for Linux/Android/macOS and Windows. Every opening
    is written to the events.
  - Off by default.

## 2.7.35

### Fixed
- Per-Site Routing → check sites, the "route through" dropdown closed by itself: the page
  redrew it on every status update (every 2 s). Now it is redrawn only when something
  changed, and never while it is open or focused.

### Changed
- The "Speed: queue and upload" card moved to the bottom of the second settings column.

## 2.7.34

### Fixed
- Gateways and address bypass showed devices that no longer exist on the router. Example:
  eth3 after the card was removed, still listed in `dns_guard.alternatives`/`metered`, shown
  as "off" with a traffic limit. The daemon no longer sends such devices to the page, and the
  page does not draw them. They stay in the settings until the settings are saved again.
- "IPv4 ⇄ IPv6" (other protocol) is no longer offered in address bypass when the router has
  no IPv6 route to the internet at all (`ip -6 route show default` is empty). Without IPv6 it
  can do nothing.

## 2.7.33

### Fixed
- An extra gateway in networks (`dns_guard.relays`, for example `node1@10.147.17.1`) was saved
  but appeared neither in "Gateway order" nor in "Address bypass of broken routes" unless the
  DNS guard mode was "targeted". Paths were found and sent to the page only in that mode.
  Now:
  - paths, including `@name` nodes, are found in any mode except off (read-only, nothing is
    configured) and shown on the page;
  - the "all traffic" gateway (overlay), including one through your own node, also works in
    "active" mode. Before, it worked only in "targeted" mode.

## 2.7.32

### Changed
- Current events, "Vulnerabilities": the count now matches the Security block. A package is
  counted once, not once per CVE: "serious 4" used to mean 3 CVEs in glib2 and 1 in docker.
  Only items with a fix are counted: a package or cgmon with an Update button, router
  settings, or LAN devices (isolation). A vulnerability with nothing to install no longer
  clutters the events.
- The "port works slower than before" note (downshift) is shown for at most 7 days after the
  port was last seen at full speed (it was 30). As before, it is shown only for WAN ports.

## 2.7.31

### Added
- A new cgmon version is announced in the current events, with an "Update to X" button,
  when auto-update is off. cgmon checks the latest GitHub release 10 minutes after start and
  then every 6 hours (not with paid traffic). It writes to the journal once per version and
  does not repeat after a restart.

### Changed
- The auto-update setting shows plain "off" / "on"; the hint explains where the update
  button is.

## 2.7.30

### Fixed
- Security block: the risk label ("FOR INFORMATION" and the like) no longer wraps onto two lines.
- A single failed request to the vulnerability database (OSV, `HTTP 000`, no response) wiped
  all package and kernel findings from the Security block: the new report kept only settings
  and LAN devices and replaced the good report. Now:
  - the OSV request is retried up to three times (pauses of 5 and 20 s);
  - if the database is still unavailable, findings for packages, the kernel and OpenWrt
    advisories are kept from the previous report, the error is shown as "not everything
    could be checked", and the check is repeated in an hour instead of in a week.

## 2.7.29

### Changed
- Router names for cgmon (`integration.names`) default to `cgmon.lan`. The field is a single
  line, so several names are separated with «;», and the hint no longer says "one per line".
- "Auto-update cgmon" is now the first row of the "cgmon: data and integration" card.

### Fixed
- Dropdown options in settings that are defined in the settings dictionary showed raw keys
  (`au_off`, `vu_stable` …) instead of text. They are now translated.
- The hint icon in the Security block shifted right from row to row, because the column was
  right-aligned and the hint texts have different lengths. The column is now left-aligned.

## 2.7.28

### Fixed
- The "fixed in X · no package yet" hint also appeared for findings where X is the
  installed version itself (Debian fixed it with a patch without changing the version, and
  the page already marks such findings separately) and for commit-hash "versions". The hint
  is now shown only when the fixed version is newer than the installed one.

## 2.7.27

### Added
- Automatic cgmon update from GitHub: new setting `auto_update` (off | on, default off),
  under "cgmon: data and integration" on the settings page.
  - When on: 10 minutes after start and then every 6 hours, cgmon checks the latest GitHub
    release. If it is newer, cgmon downloads it, verifies the SHA256 checksum, installs it
    (as an apk/opkg package or a binary, matching how cgmon is installed) and restarts.
  - Not used with paid traffic or in read-only mode. The result goes to the journal and to
    events.

### Fixed
- 2.7.25 offered "Update · from OpenWrt" for packages that were already up to date (for
  example busybox 1.37.0-r6 → 1.37.0-r6). It compared the package version without the build
  number against the full version in the OpenWrt index. Now it compares full versions,
  including `-rN`.
- Packages built per platform (dropbear, grub2 and others in
  `targets/<target>/packages`) are now looked up in the main OpenWrt repository too.
- The "fix not in the repository yet" hint now says what is going on:
  - "fixed in X · no package yet": the program's authors fixed it, but there is no package
    with the fix in the firmware repository or in OpenWrt;
  - "only in OpenWrt beta: X": the fix exists in a beta build, but beta is offered only for
    high and critical vulnerabilities.

## 2.7.26

### Fixed
- After a cgmon update, the Security block kept showing the report made by the old version,
  so the scanner's new logic did not show up until the weekly check: no "from OpenWrt"
  buttons, and findings that are now filtered out stayed visible. The report now records
  the cgmon version that made it. When the version differs, the check runs again right
  after the update (in weekly mode, not with paid traffic).

## 2.7.25

### Added
- Vulnerability fixes from the main OpenWrt repository. On forks (ImmortalWrt and others) or
  with a lagging mirror, the fixed package version may already be on downloads.openwrt.org
  while the firmware repository does not have it. When the scan finds no fix in the firmware
  repository, it looks in the main OpenWrt repository for the same branch and architecture
  (`index.json`, or `Packages` on older releases) and offers "Update to X · from OpenWrt".
  - Stable channel: the latest release of the branch, for any vulnerability.
  - Beta channel: the branch nightly builds (`<branch>-SNAPSHOT`), only for high and
    critical vulnerabilities. It is marked "OpenWrt beta", asks for an extra confirmation
    and is not included in "Update all".
- How it is installed:
  - apk adds the feed only for this command (`--repository …/packages.adb`); opkg uses a
    temporary config in /tmp/cgmon. The router's repository list is not changed.
  - apk/opkg checks the signature with the OpenWrt key, which forks ship.
  - The feed address is taken only from the scanner's own report, never from the page.
- New setting `vuln_scan.upstream`: off | stable | beta (default beta). On the settings
  page: "Fixes from the main OpenWrt repository".

## 2.7.24

### Fixed
- Vulnerability scan: a CVE described as a flaw in one program of a source package (for
  example "sshd in OpenSSH before 10.6p2 …") is no longer reported when the OpenWrt
  subpackage with that program is not installed. A router with dropbear and only
  `openssh-sftp-server` showed CVE-2026-123158 (sshd password bypass on musl) as a high
  threat. The openssh programs are mapped to their subpackages: server, client,
  client-utils, keygen, sftp-client and sftp-server. Generic descriptions ("In OpenSSH …")
  are kept as before.
- Vulnerability report: when a fixed version exists but the router's firmware repository
  does not have it yet, the package shows "fix not in the repository yet" with an
  explanation instead of no button at all. The Update button appears once the package
  reaches the repository.

## 2.7.23

### Added
- lighttpd support: with `lighttpd-mod-cgi` installed, cgmon adds
  `/etc/lighttpd/conf.d/90-cgmon.conf`, which runs `/cgi-bin/api_*` as CGI, and reloads
  lighttpd. The scripts talk to the daemon through a root-only socket, so lighttpd must run
  as root. If `server.username` is set, the log explains what to change.
- `cgmon web-setup` configures the router's web server for cgmon right away and prints what it
  found and did. The daemon also runs this check at start and once a minute.

### Checked
- On an OpenWrt 25.12.6 test system, the page and all `api_*` endpoints (GET, POST body, query
  string, client address) behave the same on uhttpd (default config and Gargoyle's config;
  Gargoyle uses uhttpd), nginx + uwsgi (luci-nginx) and lighttpd. Without the fix, nginx and
  lighttpd return the script text. Apache in OpenWrt serves `/usr/share/apache2/htdocs`
  rather than `/www` and is not used for the router UI, so it is not configured.

## 2.7.22

### Fixed
- Routers that serve the web interface with nginx (luci-nginx) instead of uhttpd showed an
  empty page: nginx does not run CGI scripts, so `/cgi-bin/api_*` returned the script text
  (`#!/bin/sh…`) and the page failed with "Unexpected token '#' … is not valid JSON". cgmon
  now detects nginx with the uwsgi CGI plugin (what LuCI uses under nginx) and adds its own
  uwsgi vassal `/etc/uwsgi/vassals/cgmon-cgi.ini` and `/etc/nginx/conf.d/cgmon.locations`
  for `/cgi-bin/api_*`, then reloads nginx once. The CGI root is the real location of the
  scripts (`/tmp/cgmon/www`), because uwsgi refuses to run a symlinked script outside its
  root. If nginx has no uwsgi CGI plugin, the log says what to install. `--uninstall` removes
  both files. Routers with uhttpd are not affected.

## 2.7.21

### Fixed
- The WAN chart kept a gap after the tab had been in the background or the computer had
  slept: router history was loaded only once, when the page opened, and only before the first
  live point. Now any gap is filled with the router's 2-second points from its last-hour
  history; live browser points are kept. The page notices a wake-up in two ways: the tab
  becomes visible again, or the timer clock jumps (sleep with the tab open). After 30 minutes
  or more away the whole page reloads, unless settings are being edited or the full
  vulnerability report window is open; then only the chart is refilled.

## 2.7.20

### Changed
- Settings: the «Extra gateways in networks» card moved from the second column to the first,
  right under «Gateways».

## 2.7.19

### Changed
- Current events are split into two columns by height instead of alternating left and
  right. The page measures each event at the column width and balances the columns, so a
  long event (e.g. the Per-Site Routing site list) no longer leaves a gap opposite it. The
  order by importance is kept inside each column, and the most important event stays top
  left. Phones still get one column.

## 2.7.18

### Added
- Router DNS self-healing (`dns_guard.local_heal`: off | observe | active, default active;
  Settings → cgmon: data and integration). Once a minute cgmon asks dnsmasq for a random
  non-existent name, so the answer cannot come from a cache. After three failures in a row
  (timeout, SERVFAIL, REFUSED), and only if public DNS still answers directly, cgmon finds
  the service that is not answering and restarts it:
  - a local upstream of dnsmasq (SmartDNS, AdGuard Home…), identified by the process on
    its port;
  - or dnsmasq itself.
  At most once in 15 minutes and 4 times a day; every step goes to the journal. Seen in the
  field: SmartDNS answered SERVFAIL to everything from boot. Without DNS, NTP could not
  resolve its servers, so the clock drifted by 82 minutes, the hub rejected reports for
  clock skew, and tailscale could not reach its control server.

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
