#!/bin/bash
# Пакеты OpenWrt из готовых бинарников: .apk (OpenWrt/ImmortalWrt 25+, apk v3) и
# .ipk (24.10 и раньше, opkg).
#   tools/mkpkg.sh <версия> <каталог с cgmon-<сборка>-linux-<арх>>
# Пакет: /opt/cgmon/cgmon + /etc/init.d/cgmon (как у cgmon --install). arch — noarch/all:
# бинарник статический, а подходит ли процессор, проверяет скрипт перед установкой
# (DISTRIB_ARCH из /etc/openwrt_release) — чужую архитектуру он не поставит.
# После установки: нет /etc/cgmon/cgmon.yaml — минимальный (всё по умолчанию, только
# наблюдение), служба включается и (пере)запускается. Удаление — cgmon --uninstall.
# apk v3 собирает apk.static из Alpine (apk-tools-static 3.x; APK=… — свой путь).
set -euo pipefail
cd "$(dirname "$0")/.."
VER=$1
DIST=$2
OUT=$DIST/packages
APK=${APK:-tmp/apktool/x/sbin/apk.static}
if [ ! -x "$APK" ]; then
	mkdir -p tmp/apktool
	idx=$(curl -fsS https://dl-cdn.alpinelinux.org/alpine/edge/main/x86_64/APKINDEX.tar.gz | tar xzO APKINDEX | grep -A1 '^P:apk-tools-static$' | sed -n 's/^V://p')
	curl -fsS -o tmp/apktool/ats.apk "https://dl-cdn.alpinelinux.org/alpine/edge/main/x86_64/apk-tools-static-$idx.apk"
	mkdir -p tmp/apktool/x && tar xzf tmp/apktool/ats.apk -C tmp/apktool/x 2>/dev/null
	APK=tmp/apktool/x/sbin/apk.static
fi
# сборка дерева — на разделе Linux (права и владелец root через unshare -r)
WORK=${PKG_WORK:-$HOME/.cache/cgmon-pkg}
rm -rf "$WORK" "$OUT"
mkdir -p "$WORK" "$OUT"

# архитектура бинарника → какие DISTRIB_ARCH OpenWrt подходят
archs() {
	case $1 in
	x86_64) echo 'x86_64*' ;;
	i686) echo 'i386_pentium4*|i686*' ;;
	aarch64) echo 'aarch64*' ;;
	armv7) echo 'arm_cortex-a*' ;;
	armv5te) echo 'arm_arm926ej-s*|arm_xscale*|arm_arm1176jzf-s*|arm_mpcore*' ;;
	mips) echo 'mips_24kc*|mips_74kc*' ;;
	mipsel) echo 'mipsel_24kc*|mipsel_74kc*|mipsel_1004kc*' ;;
	esac
}

for bin in "$DIST"/cgmon-*-linux-*; do
	b=$(basename "$bin")
	v=${b#cgmon-}; v=${v%%-linux-*}           # full | lite | nano
	a=${b##*-linux-}                          # x86_64 | mipsel | …
	pat=$(archs "$a")
	[ -n "$pat" ] || { echo "mkpkg: неизвестная архитектура $a" >&2; exit 1; }
	name=cgmon; [ "$v" = full ] || name=cgmon-$v
	others=$(for x in cgmon cgmon-lite cgmon-nano; do [ "$x" = "$name" ] || printf '%s ' "$x"; done)
	d=$WORK/$name-$a
	mkdir -p "$d/root/opt/cgmon" "$d/root/etc/init.d" "$d/ctl"
	cp "$bin" "$d/root/opt/cgmon/cgmon"
	cp openwrt/cgmon.init "$d/root/etc/init.d/cgmon"
	find "$d/root" -type d -exec chmod 755 {} +
	chmod 755 "$d/root/opt/cgmon/cgmon" "$d/root/etc/init.d/cgmon"

	cat > "$d/ctl/preinst" <<EOF
#!/bin/sh
# сборка образа (ImageBuilder) — процессор не проверять
[ -n "\${IPKG_INSTROOT:-}" ] && exit 0
DISTRIB_ARCH=
[ -f /etc/openwrt_release ] && . /etc/openwrt_release
arch=\${DISTRIB_ARCH:-\$(uname -m)}
case "\$arch" in
	$pat) exit 0 ;;
esac
echo "$name: this package is for $a, but the router is \$arch — take the package for your architecture" >&2
exit 1
EOF
	cat > "$d/ctl/postinst" <<'EOF'
#!/bin/sh
[ -n "${IPKG_INSTROOT:-}" ] && exit 0
mkdir -p /etc/cgmon
if [ ! -f /etc/cgmon/cgmon.yaml ]; then
	printf '%s\n' '# cgmon.yaml — created by the package: all defaults (observe only).' \
		'# Page password: LuCI -> Services -> cgmon. All options: cgmon --install, config.reference.yaml.' > /etc/cgmon/cgmon.yaml
	chmod 600 /etc/cgmon/cgmon.yaml
fi
/etc/init.d/cgmon enable
/etc/init.d/cgmon restart
echo "cgmon is running: http://<router>/status.html (set the page password in LuCI -> Services -> cgmon)"
exit 0
EOF
	cat > "$d/ctl/prerm" <<'EOF'
#!/bin/sh
[ -n "${IPKG_INSTROOT:-}" ] && exit 0
# обновление — служба остаётся (postinst перезапустит)
[ "${1:-}" = upgrade ] && exit 0
/opt/cgmon/cgmon --uninstall >/dev/null 2>&1
exit 0
EOF
	chmod 755 "$d/ctl/"*
	desc="cgmon $v: monitor for OpenWrt routers — loads kernel rules (nftables, ip rules/routes, tc, DNS) and watches"
	size=$(du -sk "$d/root" | cut -f1)

	# .apk (apk v3): owner root через user namespace
	unshare -r "$APK" mkpkg \
		--info "name:$name" --info "version:$VER-r1" --info arch:noarch \
		--info "description:$desc" --info license:GPL-3.0-or-later \
		--info url:https://github.com/real4root/cgmon \
		--info "depends:$(for x in $others; do printf '!%s ' "$x"; done)" \
		--files "$d/root" \
		--script "pre-install:$d/ctl/preinst" --script "post-install:$d/ctl/postinst" \
		--script "pre-upgrade:$d/ctl/preinst" --script "post-upgrade:$d/ctl/postinst" \
		--script "pre-deinstall:$d/ctl/prerm" \
		--output "$OUT/$name-$VER-r1-$a.apk"

	# .ipk (opkg): tar.gz из debian-binary, control.tar.gz, data.tar.gz — владелец root
	cat > "$d/ctl/control" <<EOF
Package: $name
Version: $VER-1
Conflicts: $(echo $others | sed 's/ /, /g')
Source: https://github.com/real4root/cgmon
License: GPL-3.0-or-later
Section: net
Architecture: all
Installed-Size: $((size * 1024))
Description: $desc
EOF
	python3 - "$d" "$OUT/${name}_$VER-1_$a.ipk" <<'PY'
import io, os, sys, tarfile, time
d, out = sys.argv[1], sys.argv[2]
now = int(time.time())
def add(t, path, arc):
    ti = t.gettarinfo(path, arc)
    ti.uid = ti.gid = 0
    ti.uname = ti.gname = 'root'
    ti.mtime = now
    if ti.isfile():
        with open(path, 'rb') as f:
            t.addfile(ti, f)
    else:
        t.addfile(ti)
def tgz(files):
    b = io.BytesIO()
    with tarfile.open(fileobj=b, mode='w:gz', format=tarfile.GNU_FORMAT) as t:
        for path, arc in files:
            add(t, path, arc)
    return b.getvalue()
ctl = [(f'{d}/ctl', '.')] + [(f'{d}/ctl/{n}', f'./{n}') for n in ('control', 'preinst', 'postinst', 'prerm')]
data = []
for root, dirs, files in os.walk(f'{d}/root'):
    dirs.sort()
    rel = os.path.relpath(root, f'{d}/root')
    data.append((root, '.' if rel == '.' else './' + rel))
    for n in sorted(files):
        data.append((os.path.join(root, n), ('./' + n) if rel == '.' else f'./{rel}/{n}'))
parts = [('debian-binary', b'2.0\n'), ('data.tar.gz', tgz(data)), ('control.tar.gz', tgz(ctl))]
with tarfile.open(out, 'w:gz', format=tarfile.GNU_FORMAT) as t:
    for n, body in parts:
        ti = tarfile.TarInfo('./' + n)
        ti.size, ti.mtime, ti.mode, ti.uname, ti.gname = len(body), now, 0o644, 'root', 'root'
        t.addfile(ti, io.BytesIO(body))
PY
done
(cd "$OUT" && sha256sum *.apk *.ipk > SHA256SUMS)
echo "пакеты: $(ls "$OUT" | grep -c 'k$') в $OUT"
