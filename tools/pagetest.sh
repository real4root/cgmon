#!/bin/bash
# Проверка www/status.html на данных живого роутера — всё внутри проекта (tmp/).
#
#   tools/pagetest.sh <ssh-хост> [имя] [ширина] [js]
#
# Снимает с роутера статус, api_router и историю графика (api_hist) в
# tmp/web/<имя>/cgi-bin/, кладёт рядом текущий www/status.html, поднимает
# локальный http.server (порт по имени) и делает скриншот Windows-Chrome в
# tmp/shots/<имя>.png; в вывод — ошибки консоли страницы. Необязательный js
# выполняется на странице через 4 с (например "portPop('eth0')").
# Windows-Chrome не видит ZeroTier-хосты — поэтому данные копируются, а
# страница открывается с localhost.
set -e
ROOT=$(cd "$(dirname "$0")/.." && pwd)
HOST=${1:?ssh-хост}
NAME=${2:-$(echo "$HOST" | sed 's/.*@//; s/[^A-Za-z0-9_-]/_/g')}
WIDTH=${3:-1400}
JS=$4
W=$ROOT/tmp/web/$NAME
mkdir -p "$W/cgi-bin" "$ROOT/tmp/shots"
strip_hdr() { sed '1,/^\r\{0,1\}$/d'; }
# «страницу смотрят» — тогда в статусе и порты, и TOP (на слабых роутерах — по кнопке)
ssh -o ConnectTimeout=8 "$HOST" 'touch /tmp/cgmon/web_hb; sleep 6; cat /var/run/cgmon.status.json' > "$W/cgi-bin/api_status"
ssh -o ConnectTimeout=8 "$HOST" 'REQUEST_METHOD=GET /www/cgi-bin/api_router' | strip_hdr > "$W/cgi-bin/api_router" || true
ssh -o ConnectTimeout=8 "$HOST" 'cd /www/cgi-bin && QUERY_STRING=sec=3600 ./api_hist' | strip_hdr > "$W/cgi-bin/api_hist" || true
if [ -n "$JS" ]; then
	# & и | в js — экранировать для sed
	JSE=$(printf '%s' "$JS" | sed 's/[&|\\]/\\&/g')
	sed "s|</body>|<script>setTimeout(() => { $JSE }, 4000)</script></body>|" "$ROOT/www/status.html" > "$W/status.html"
else
	cp "$ROOT/www/status.html" "$W/status.html"
fi
PORT=$((8800 + $(printf '%s' "$NAME" | cksum | cut -d' ' -f1) % 100))
if ! (exec 3<>/dev/tcp/127.0.0.1/$PORT) 2>/dev/null; then
	(cd "$W" && nohup python3 -m http.server "$PORT" >/dev/null 2>&1 &)
	sleep 1
fi
WIN=$(wslpath -w "$ROOT/tmp/shots/$NAME.png")
timeout 60 "/mnt/c/Program Files/Google/Chrome/Application/chrome.exe" --headless=new --disable-gpu \
	--enable-logging=stderr --v=0 --virtual-time-budget=9000 --window-size="$WIDTH,1600" \
	--screenshot="$WIN" "http://localhost:$PORT/status.html" 2>&1 | grep CONSOLE | grep -v 'Password field' || true
echo "скриншот: $ROOT/tmp/shots/$NAME.png (http://localhost:$PORT/status.html)"
