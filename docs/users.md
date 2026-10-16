# cgmon in plain language

**English** · [Русский](users.ru.md)

This guide is for people who don't configure networks every day. Technical
details live in the [README](../README.md).

## What it is

A router is the little box that connects all your phones, laptops and TVs to the
internet. Inside it runs a small Linux computer that works like a post office:
it sorts and dispatches "letters" — small pieces of data.

**cgmon is the watchman and dispatcher inside the router.** It never carries the
letters itself — Linux still does that. cgmon keeps an eye on whether everything
is fine and, when something breaks, gives Linux new instructions, such as "send
letters for this site by another road". That is why the internet keeps working
even if cgmon is switched off: the router simply follows the last instructions.

Everything cgmon sees and does is shown on the router's web page:
`http://<router address>/status.html`.

## What it does

### Watches whether the internet is alive

Every few seconds the router "knocks" on several reliable servers on the
internet. If they answer, all is well. If they stop answering, the problem is on
the provider's side, and cgmon records it in the journal in plain words — for
example, "new connections failed for 3 minutes — provider outage".

Internet states on the page:

- **NORMAL** — everything is fine;
- **WARNING** — something is starting to misbehave;
- **CRITICAL** — a serious outage;
- **RECOVERY** — the outage is over and the internet is getting back to normal.

### Two roads to the internet: IPv4 and IPv6

Every device on the internet has an address, just like a house. Addresses come
in two kinds: the old ones (**IPv4**, like `1.2.3.4`) and the new ones (**IPv6**,
long, with colons). Think of them as two different roads leading to the same
sites. Sometimes a provider breaks one road while the other keeps working. cgmon
checks both separately and compares them.

### Tells you which site is down

Sometimes the internet as a whole works, but one site or app won't open. cgmon
notices which sites the devices at home try and fail to reach, and reports:
"such-and-such service is not answering". That way you can see the site is
broken, not your internet. This is called a **down detector**.

### Shows your devices and who is using the bandwidth

The page has a table of every device at home: phone, laptop, TV… cgmon tries to
learn their names on its own (say, "Mary's iPhone") or at least the
manufacturer. You can see who is loading the connection the most right now and
how much each device downloaded in the last hour and day. There is also a chart
where every device gets its own line.

### Finds "lost" devices

Brought home an old IP camera and nobody remembers its address? If the address
belongs to another network (say, `192.168.1.64` while your home uses
`192.168.10.x`), your computer simply can't see it. Start **cgfinder**, plug the
camera into the router by cable or Wi-Fi, and within a minute or two a line
appears under the device table: the camera's address, its manufacturer and an
"Open access" button. Press it, and for one hour the camera opens in a browser
on any computer or phone at home — nothing on them needs reconfiguring. You
don't even need to know the camera's address or password in advance: the router
hears the camera "calling" for its old router.

### Counts billed traffic

Some providers give part of the internet for free and bill the rest by the
megabyte. cgmon can count how much billed traffic went out today and this month
and warn you when you are close to the limit.

Which networks are free depends on the provider. The list can be downloaded from
a link (for Uzbekistan the TAS-IX list is already set) or uploaded as a file right
from the page: a plain text file with one network per line. Providers usually
publish such a list on their website.

### A smart queue that keeps the internet snappy (SQM)

Picture a supermarket checkout. One shopper unloads a cart of a hundred items,
and behind them stands someone who only needs a bottle of water. Without some
order, the second person waits a long time.

The internet works the same way: when someone at home downloads a big file or
uploads a video, games, video calls and websites slow down for everyone else.
**SQM** ("smart queue management") is a polite cashier: it lets small, urgent
purchases go first and shares the line fairly. Calls and games stay smooth even
while someone is downloading.

### Upload shaper and penalty detector

Some providers "punish" a subscriber who sends data out too fast for too long
(uploading big files, for instance): the speed then drops to almost nothing for a
long time. The **upload shaper** is a speed limiter that gently slows uploads down
so the provider has no reason to punish you. The **penalty detector** notices when
it happened anyway and records it.

### A brake for "greedy" devices

Providers sometimes limit how many connections you may have open at once. A
torrent client can open thousands at a time, and then sites stop opening for
everyone else at home. cgmon finds the greediest device and stops it from opening
new connections until things calm down. Downloads already in progress are never
cut off. By default this mode only reports what it would do and limits nothing.

### Backup internet

If a second internet connection is plugged into the router (a mobile modem, for
example), cgmon finds it by itself and can switch over when the main one breaks,
then switch back once it is fixed. Right after installation it only shows what
it would do; switching is turned on separately.

### DNS guard

When you type `google.com`, your device first asks **DNS** — the internet's phone
book, which turns a site's name into its address. For many sites the book lists
addresses of both kinds, IPv4 and IPv6.

If the provider breaks one road (IPv6, say), devices still try to take it, and
sites load slowly or not at all. At that moment cgmon "hides" the broken road's
addresses from the phone book, and every device immediately takes the working
road. Once the road is fixed, everything goes back to how it was.

**Targeted mode** is more precise: it hides the bad road not for the whole
internet but only for the sites that are having trouble right now. If Google's
IPv6 is misbehaving, only Google is affected and every other site notices
nothing.

### Detours around broken routes

Data travels to a site through many other people's nodes, like a car through
city streets. Sometimes it's not the whole internet that breaks but a single
"street" on the way to one particular site. cgmon acts like a navigator that knows
about the traffic jam: it sends traffic for that site on a detour and everything
else as usual.

Possible detours:

- **mobile internet**, if a modem is connected to the router (you can set a daily
  megabyte limit so you don't overspend);
- **a VPN** (Tailscale, for example);
- **another router of yours** in another place, with another provider, if the
  routers are linked with **ZeroTier** — a program that joins routers in different
  cities into one shared "home" network. The speed through such a router can be
  capped so it doesn't get in the way of the people who live there.

You set the order of detours on the page with the mouse: which one to try first,
which one second. Before sending traffic on a detour, cgmon checks that the site
doesn't merely "answer" along that road but actually loads. If it doesn't, the
next detour is tried.

### Finds where exactly things broke

When one of the roads works badly, cgmon checks the path to several sites, good
and bad, node by node. If all the bad paths go through the same place while the
good ones avoid it, it reports: "common culprit — the junction between such-and-such
provider and such-and-such network". Now you know whose side the problem is on and
whom to complain to.

### Per-site scores

cgmon gives both roads (IPv4 and IPv6) a score from 0 to 100. It doesn't look at a
couple of test servers but at the sites people at home actually use. That is how
it tells "the whole road is broken" from "a couple of sites don't work".

### "Current events"

Above the chart, one line each, you see only what matters right now: which sites
were sent on a detour, whether the router switched to backup internet, what broke
on the provider's side. When everything is fine, this block is hidden.

### Tenants

If you rent out part of your home and the tenants have a separate network, they
can open the same page but will see only their own devices — not yours, and not
the settings.

### Several routers and Telegram alerts

If you have several routers (at home, at your relatives', at the cottage), they can
send their reports to one main router — the **collection hub**. The hub works out
whether the internet broke at one provider only or everywhere at once, and tells
you in Telegram. Data between the routers is encrypted.

### Payment reminders

The hub can remind you in Telegram that it's time to pay for the internet.

### Settings right on the page

Almost everything can be changed on the router's page without a reboot — all it
takes is the password. After five wrong passwords the page pauses so the password
can't be guessed. Until a password is set, the page is view-only — nothing can be
changed from it. The password is set in the router's web interface (LuCI):
**Services → cgmon**, together with the hub address and Telegram.

Where accumulated data (traffic accounting and the like) is kept is a setting:
in the router's flash (nothing is lost, but the flash wears out), in RAM (no wear,
but everything starts from zero after a reboot) or on a USB stick.

## Which build to choose

- **full** — everything. For an x86 router or a powerful ARM one.
- **lite** — everything except SmartDNS and what depends on it (targeted DNS guard,
  detours around broken routes). For ordinary home routers.
- **nano** — for weak routers with little firmware memory (for example, the TP-Link
  TL-WR1043N/ND): it runs on what already comes with the firmware. The smart queue
  (SQM) can be added later — about 240 KB.

If a feature is missing a program, the page says "requires …", and "Current
events" shows an **Install** button — the router installs the package by itself
(you need the page password and an internet connection).

## Is it safe?

- Right after installation cgmon **only watches**: it blocks nothing, limits
  nothing and sends nothing anywhere. Every action is turned on separately.
- If cgmon is switched off or breaks, the internet keeps working.
- Passwords and keys are stored only in the settings file on the router itself
  and are never shown on the page.
- Router journal messages are currently written in Russian; the page itself is
  available in English.

## A small glossary

| Word | Meaning |
|---|---|
| Provider (ISP) | the company that gives you internet access |
| Router | the box that shares the internet at home (over Wi-Fi and cables) |
| IPv4, IPv6 | two kinds of internet addresses — like two roads to the same sites |
| DNS | the internet's "phone book": a site's name → its address |
| Connection | one "conversation" between a device and a site; a single page may open dozens |
| Traffic | how much data was downloaded or sent |
| Upload, download | sending data from home to the internet, and receiving it from the internet |
| SQM | "smart queue": shares the line fairly so calls and games don't lag |
| Shaper | a speed limiter |
| VPN | a protected "tunnel" to another place on the internet |
| ZeroTier, Tailscale | programs that join your routers and devices into one network over the internet |
| Incident journal | a list of every outage: when it started, when it ended, what happened |
| Telegram bot | a program that sends you messages in Telegram |
