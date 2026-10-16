# The cgmon collection hub and reporting

**English** · [Русский](hub.ru.md)

Every router running cgmon can report its state to one or more **collection
hubs**. A hub is simply a router running cgmon with "Main collection hub" switched
on. It correlates the data from all routers and sends Telegram alerts when a
failure shows up in many places at once — which is how "my provider or router is
broken" is told apart from "the country's upstream link is down".

## What a router sends

Once a minute and immediately on any change:

- WAN state (NORMAL / WARNING / CRITICAL / RECOVERY) and the diagnosis;
- IPv4/IPv6 probes (success rate, latency);
- open and recent incidents (last 3 hours, up to 20);
- services that are not answering clients or answer slowly (down detector), with
  the protocol (IPv4/IPv6);
- which link the router is using right now (gateway selector) and whether it is a
  backup;
- its provider: the public IP (OpenDNS over DNS, or https://api.ipify.org if DNS is
  intercepted) and its autonomous system (Team Cymru over DNS).

Client devices, their traffic and their names are **never sent**.

## What the hub does

Every 10 seconds it compares the latest reports and posts to Telegram:

| Icon | Event | When |
|---|---|---|
| 🔴 | Upstream outage | WAN degraded at the same time on routers of ≥ `min_isps` (2) different providers |
| 🟠 | Outage at provider X | ≥ 2 routers of one provider, while other providers are fine |
| 🟡 | Service down / slow | the same site or service is bad on ≥ 2 routers (any providers); the text says whether it is one provider or several |
| ⚫ / 🟢 | Router offline / back online | no reports for longer than `stale_sec` (180 s) |
| 🟢 | Recovered | with the outage duration and the routers/providers affected |

A failure on a single router is not sent to Telegram by default
(`notify_single: true` changes that). The hub's page has a "🌍 Collection hub"
section: a table of routers (provider, state, probes, last report, version) and the
**global incident journal**; "Current events" lists routers that are offline,
routers running entirely on a backup link, outages across several providers and
services failing on ≥ 2 routers.

## Router health and the issues window

Besides its WAN state, a router (2.4+) sends a list of current issues, each marked
"warning" or "critical":

| Issue | Level |
|---|---|
| WAN: no connectivity / CRITICAL | critical |
| WAN: WARNING | warning |
| port: link drops within the last hour | critical |
| port: frame errors within the hour; speed below what it can do (cable, downshift) | warning |
| internet over a backup link | warning |
| mass connection failures to sites; a common culprit on the path | warning |
| DNS guard in protocol-wide mode; all IPv6 refused | warning |
| router overloaded, low memory, SoC temperature ≥ 75 °C (≥ 85 °C — critical) | warning |
| packages missing for enabled features | warning |

A router's status in the hub table is the worst of its WAN phase and its issues
(NORMAL / WARNING / CRITICAL / OFFLINE), with the number of issues. Clicking the
status opens a window with the descriptions. A new critical issue goes to
Telegram; everything else, and "resolved", goes to the hub journal.

## Removing a router from the hub

The router name in the table is a link to its page: the hub remembers the address
the last report came from (usually a ZeroTier address) and opens
`http://<address>/status.html`. Clicking the status opens the router's issues
window. Clicking the version opens an info window (version, provider and AS,
report address, last report, WAN) with a "Remove from hub" button (requires the
hub page password): the router, its place in open outages and its reminders are
deleted. If the router reports again (after a reinstall, for example), it simply
reappears. Routers that have been silent for 30 days are removed automatically. A
reinstalled router with the same `report.name` continues its history under the
same name.

## Port and firewall

The hub listens on **TCP 7788** (`hub.listen`, configurable). TCP only, this port
only.

- Routers in the same network as the hub (ZeroTier / Tailscale) need nothing
  opened; the hub address is its tunnel address:
  `http://10.0.0.1:7788/api/v1/report`.
- A hub on the internet needs inbound TCP 7788 open on WAN. On OpenWrt:

```sh
uci add firewall rule
uci set firewall.@rule[-1].name='cgmon-hub'
uci set firewall.@rule[-1].src='wan'
uci set firewall.@rule[-1].proto='tcp'
uci set firewall.@rule[-1].dest_port='7788'
uci set firewall.@rule[-1].target='ACCEPT'
uci commit firewall && fw4 reload
```

A router behind CGNAT (a 100.64.x.x address from the provider) cannot be reached
from the internet, so an internet-facing hub needs a public IP (a VPS) or a port
forward.

## Security

The hub is designed to be exposed to the internet.

- **Every report is encrypted and authenticated**: AES-256-GCM with a key derived
  as SHA-256 of a shared secret. The secret never travels over the network; without
  it a report cannot be read, forged or altered (a tampered packet is rejected). TLS
  is not used (no certificate needed), hence the `http://` address.
- **Replay protection**: each report carries a timestamp (±5 minutes tolerance) and
  nonces are remembered, so a captured packet is never accepted twice. All routers
  need correct clocks (NTP is on by default in OpenWrt).
- **Overload protection**: at most 64 concurrent connections and 8 per address, 120
  requests per minute per address, 10 seconds for a whole request, a request line
  and each header ≤ 4 KB (longer ones close the connection instead of piling up in
  memory), at most 64 headers, a body ≤ 64 KB and at most 500 routers. Rejected
  requests are logged at most once a minute.
- **Report contents are checked** even with a valid token, in case a router
  misbehaves: ≤ 50 incidents/services, short fields ≤ 128 bytes, incident text
  truncated to 2000 bytes, and the hub's memory for incident ids and reminders is
  bounded.
- **Nothing extra leaks out**: every error gets the same bare 403 response; the hub
  state is never served over the network (only on the router itself, from
  127.0.0.1, and on its page).
- **Texts on the hub page are escaped**: a router name from a report cannot inject
  code into the page.

Limitations:

- the secret is **shared** by the hub and all its routers: if it leaks from any
  router, fake reports can be sent (but nobody else's alerts can be read). If in
  doubt, generate a new one and replace it everywhere;
- connection metadata (which IP talks to which hub) is visible to the network.

## Setup

### The secret

One per hub and all its routers, at least 16 characters:

```sh
head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n'
```

The wizard (`cgmon --advanced-install`) generates one if the field is empty.

### The hub — in `/etc/cgmon/cgmon.yaml`

```yaml
hub:
  enabled: true                 # or the page switch "This router is the main collection hub"
  listen: ":7788"
  token: "<secret>"
  telegram:                     # several bots, each with several recipients
    - bot_token: "<bot 1 token>"
      chat_ids: ["123456789", "-1001234567890"]   # direct chat, group (-100…), channel (@name)
    - bot_token: "<bot 2 token>"
      chat_ids: ["<id>"]
  stale_sec: 180
  min_isps: 2
  notify_single: false
  notify_offline: true
```

### Routers

```yaml
report:
  enabled: true                 # or the page switch "Send data to hubs"
  urls:                         # several hubs are fine — data goes to all of them
    - http://10.0.0.1:7788/api/v1/report
    - http://203.0.113.10:7788/api/v1/report
  token: "<secret>"
```

Secrets are set only in `cgmon.yaml` (mode 0600) and never appear on the page. The
list of hubs and the switches can be changed from the page without a restart. The
page password, hub and Telegram can also be set in LuCI under **Services → cgmon**.

### Telegram

1. Message [@BotFather](https://t.me/BotFather) → `/newbot` → get the bot token.
2. Send the bot any message (or add it to a group).
3. Find the chat id: `curl -s https://api.telegram.org/bot<token>/getUpdates` —
   the `"chat":{"id": …}` field (negative for groups).
4. Put the bot and the chats into `hub.telegram` and restart cgmon.
5. Test it: `cgmon telegram-test` sends a test message to every recipient.

Every alert goes to every "bot → chat" pair. Each recipient has its own retry
queue, so an unreachable bot or chat does not hold up the others. The old fields
`telegram_bot_token`/`telegram_chat_id` (one bot, one chat) still work.

Until a bot is configured, alerts are written only to the hub log
(`logread | grep hub`) and to the "Collection hub" section of the page. Telegram
messages are sent with curl, uclient-fetch or wget, whichever is installed (with
curl the token is passed over stdin and never shows up in the process list). If
Telegram is unreachable, sending is retried every 10 seconds with a queue of up to
100 messages. Alert texts are currently in Russian.

## Checking

- On a router, in the page "Settings", under the hub addresses: how many reports
  were sent to each hub and the last error, if any.
- On the hub: the "🌍 Collection hub" section, `logread | grep hub`,
  `printf 'GET /api/state HTTP/1.1\r\nContent-Length: 0\r\n\r\n' | nc 127.0.0.1 7788`.
- Hub files: `/etc/cgmon/hub_state.json` (routers, open outages, journal) and
  `/tmp/cgmon/hub.jsonl` (every incident accepted from every router).
