'use strict';
'require view';
'require form';
'require fs';
'require ui';

// cgmon — LuCI «Службы → cgmon»: пароль страницы мониторинга и центр сбора.
// Данные и запись — через сам cgmon (luci-get / luci-set); остальные настройки —
// на странице мониторинга /status.html. Ставит cgmon при запуске (src/luci.rs).

var BIN = '__CGMON_BIN__';

function okFlag(v) { return v === '1' || v === true; }

return view.extend({
	load: function() {
		return fs.exec_direct(BIN, [ 'luci-get' ], 'json').catch(function(e) {
			return { error: e.message || String(e) };
		});
	},

	render: function(st) {
		if (!st || st.error)
			return E('div', { 'class': 'alert-message warning' }, _('cgmon не отвечает: ') + ((st && st.error) || ''));

		this.st = st;
		var r = st.report || {}, h = st.hub || {}, w = st.web || {};
		var data = { main: {
			password: '', password2: '',
			report_enabled: r.enabled ? '1' : '0', report_urls: r.urls || [], report_token: '', report_name: r.name || '',
			hub_enabled: h.enabled ? '1' : '0', hub_token: '', tg_bot: '', tg_chat: h.tg_chat || ''
		} };
		var m = new form.JSONMap(data, 'cgmon',
			_('Монитор канала, устройств и портов. Здесь — пароль страницы мониторинга и центр сбора: их нельзя менять со страницы. Всё остальное настраивается на ней самой.'));
		var s = m.section(form.NamedSection, 'main', 'main');
		s.tab('page', _('Страница мониторинга'));
		s.tab('report', _('Отправка на центр сбора'));
		s.tab('hub', _('Этот роутер — центр сбора'));

		var o = s.taboption('page', form.DummyValue, '_state', _('Состояние'));
		o.rawhtml = true;
		o.cfgvalue = function() {
			return '<b>cgmon ' + st.version + '</b> · ' + (st.running ? _('работает') : '<span style="color:#c00">' + _('не запущен') + '</span>')
				+ ' · <a href="/status.html" target="_blank">' + _('открыть страницу мониторинга') + ' →</a>';
		};
		o = s.taboption('page', form.Value, 'password', _('Новый пароль'),
			w.password_set
				? _('Пароль задан. Оставьте поле пустым, чтобы не менять.')
				: '<b style="color:#c60">' + _('Пароль не задан: страница мониторинга только показывает — менять настройки с неё нельзя.') + '</b>');
		o.password = true;
		o.rmempty = true;
		o = s.taboption('page', form.Value, 'password2', _('Ещё раз'), _('От 6 символов. Нужен, чтобы менять настройки на странице мониторинга.'));
		o.password = true;
		o.rmempty = true;

		o = s.taboption('report', form.Flag, 'report_enabled', _('Отправлять отчёты'),
			_('Состояние канала, проблемы и инциденты уходят на центр сбора (зашифровано, токен по сети не передаётся). Центр сообщает о сбоях в Telegram.'));
		o = s.taboption('report', form.DynamicList, 'report_urls', _('Адреса центров'),
			_('Пример: http://10.147.17.5:7788/api/v1/report — адрес центра в ZeroTier/Tailscale или в интернете. Можно несколько.'));
		o.depends('report_enabled', '1');
		o.placeholder = 'http://10.147.17.5:7788/api/v1/report';
		o = s.taboption('report', form.Value, 'report_token', _('Токен'),
			r.token_set ? _('Задан. Пусто — не менять. Должен совпадать с токеном центра.') : _('Общий секрет с центром, от 16 символов. Должен совпадать с токеном центра.'));
		o.password = true;
		o.depends('report_enabled', '1');
		o = s.taboption('report', form.Value, 'report_name', _('Имя роутера'),
			_('Как роутер будет называться на центре. Пусто — имя системы: ') + (r.hostname || ''));
		o.placeholder = r.hostname || '';
		o.depends('report_enabled', '1');

		o = s.taboption('hub', form.Flag, 'hub_enabled', _('Принимать отчёты (центр сбора)'),
			_('Этот роутер собирает отчёты других роутеров на порту ') + (h.listen || ':7788') + _(' (TCP) и показывает их на своей странице мониторинга.'));
		o = s.taboption('hub', form.Value, 'hub_token', _('Токен центра'),
			h.token_set ? _('Задан. Пусто — не менять.') : _('От 16 символов; такой же токен — у роутеров, которые шлют отчёты.'));
		o.password = true;
		o.depends('hub_enabled', '1');
		if (h.tg_list > 0) {
			o = s.taboption('hub', form.DummyValue, '_tg', _('Telegram'));
			o.cfgvalue = function() { return _('настроен списком в cgmon.yaml (hub.telegram), ботов: ') + h.tg_list; };
			o.depends('hub_enabled', '1');
		} else {
			o = s.taboption('hub', form.Value, 'tg_bot', _('Telegram: токен бота'),
				h.tg_bot_set ? _('Задан. Пусто — не менять.') : _('От @BotFather, вида 123456789:AA…'));
			o.password = true;
			o.depends('hub_enabled', '1');
			o = s.taboption('hub', form.Value, 'tg_chat', _('Telegram: чат'), _('id чата или пользователя, куда слать сбои (узнать — у @userinfobot).'));
			o.depends('hub_enabled', '1');
		}
		this.map = m;
		return m.render();
	},

	handleSaveApply: function() {
		var st = this.st, map = this.map;
		return map.save().then(function() {
			var d = map.data.get('json', 'main') || {}, p = {};
			var r = st.report || {}, h = st.hub || {};
			if (d.password || d.password2) {
				if (d.password !== d.password2)
					throw new Error(_('Пароли не совпадают'));
				p['web.password'] = d.password;
			}
			if (okFlag(d.report_enabled) !== !!r.enabled) p['report.enabled'] = okFlag(d.report_enabled);
			var urls = [].concat(d.report_urls || []).filter(function(u) { return u; });
			if (JSON.stringify(urls) !== JSON.stringify(r.urls || [])) p['report.urls'] = urls;
			if (d.report_token) p['report.token'] = d.report_token;
			if ((d.report_name || '') !== (r.name || '')) p['report.name'] = d.report_name || '';
			if (okFlag(d.hub_enabled) !== !!h.enabled) p['hub.enabled'] = okFlag(d.hub_enabled);
			if (d.hub_token) p['hub.token'] = d.hub_token;
			if (d.tg_bot) p['hub.telegram_bot_token'] = d.tg_bot;
			if (d.tg_chat !== undefined && (d.tg_chat || '') !== (h.tg_chat || '')) p['hub.telegram_chat_id'] = d.tg_chat || '';
			if (!Object.keys(p).length) {
				ui.addNotification(null, E('p', _('Изменений нет')), 'info');
				return;
			}
			return fs.exec(BIN, [ 'luci-set', JSON.stringify(p) ]).then(function(res) {
				var out = {};
				try { out = JSON.parse(res.stdout || '{}'); } catch (e) {}
				if (res.code !== 0 || out.error)
					throw new Error(out.error || res.stderr || ('код ' + res.code));
				ui.addNotification(null, E('p', _('Сохранено, cgmon перезапущен')), 'info');
				window.setTimeout(function() { location.reload(); }, 2500);
			});
		}).catch(function(e) {
			ui.addNotification(null, E('p', _('Не сохранено: ') + (e.message || e)), 'error');
		});
	},

	handleSave: null,
	handleReset: null
});
