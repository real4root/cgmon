'use strict';
'require view';
'require form';
'require fs';
'require ui';

// cgmon — LuCI "Services → cgmon": monitoring-page password and the collection hub.
// Data and writes go through cgmon itself (luci-get / luci-set); every other
// setting lives on the monitoring page /status.html. Installed by cgmon at
// startup (src/luci.rs).

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
			return E('div', { 'class': 'alert-message warning' }, _('cgmon is not responding: ') + ((st && st.error) || ''));

		this.st = st;
		var r = st.report || {}, h = st.hub || {}, w = st.web || {};
		var data = { main: {
			password: '', password2: '',
			report_enabled: r.enabled ? '1' : '0', report_urls: r.urls || [], report_token: '', report_name: r.name || '',
			hub_enabled: h.enabled ? '1' : '0', hub_token: '', tg_bot: '', tg_chat: h.tg_chat || ''
		} };
		var m = new form.JSONMap(data, 'cgmon',
			_('Link, device and port monitor. Only the monitoring-page password and the collection hub are set here — they cannot be changed from the page. Everything else is configured on the page itself.'));
		var s = m.section(form.NamedSection, 'main', 'main');
		s.tab('page', _('Monitoring page'));
		s.tab('report', _('Send to a hub'));
		s.tab('hub', _('This router is a hub'));

		var o = s.taboption('page', form.DummyValue, '_state', _('Status'));
		o.rawhtml = true;
		o.cfgvalue = function() {
			return '<b>cgmon ' + st.version + '</b> · ' + (st.running ? _('running') : '<span style="color:#c00">' + _('not running') + '</span>')
				+ ' · <a href="/status.html" target="_blank">' + _('open the monitoring page') + ' →</a>';
		};
		o = s.taboption('page', form.Value, 'password', _('New password'),
			w.password_set
				? _('Password is set. Leave empty to keep it.')
				: '<b style="color:#c60">' + _('No password set: the monitoring page is view-only — settings cannot be changed from it.') + '</b>');
		o.password = true;
		o.rmempty = true;
		o = s.taboption('page', form.Value, 'password2', _('Repeat'), _('At least 6 characters. Needed to change settings on the monitoring page.'));
		o.password = true;
		o.rmempty = true;

		o = s.taboption('report', form.Flag, 'report_enabled', _('Send reports'),
			_('Link state, problems and incidents are sent to a collection hub (encrypted; the token never travels over the network). The hub reports failures to Telegram.'));
		o = s.taboption('report', form.DynamicList, 'report_urls', _('Hub addresses'),
			_('Example: http://10.147.17.5:7788/api/v1/report — a hub address in ZeroTier/Tailscale or on the internet. Several are allowed.'));
		o.depends('report_enabled', '1');
		o.placeholder = 'http://10.147.17.5:7788/api/v1/report';
		o = s.taboption('report', form.Value, 'report_token', _('Token'),
			r.token_set ? _('Set. Empty — keep it. Must match the hub token.') : _('Shared secret with the hub, at least 16 characters. Must match the hub token.'));
		o.password = true;
		o.depends('report_enabled', '1');
		o = s.taboption('report', form.Value, 'report_name', _('Router name'),
			_('How this router appears on the hub. Empty — the system hostname: ') + (r.hostname || ''));
		o.placeholder = r.hostname || '';
		o.depends('report_enabled', '1');

		o = s.taboption('hub', form.Flag, 'hub_enabled', _('Accept reports (be a hub)'),
			_('This router collects reports from other routers on port ') + (h.listen || ':7788') + _(' (TCP) and shows them on its own monitoring page.'));
		o = s.taboption('hub', form.Value, 'hub_token', _('Hub token'),
			h.token_set ? _('Set. Empty — keep it.') : _('At least 16 characters; the same token is used by the routers that send reports.'));
		o.password = true;
		o.depends('hub_enabled', '1');
		if (h.tg_list > 0) {
			o = s.taboption('hub', form.DummyValue, '_tg', _('Telegram'));
			o.cfgvalue = function() { return _('configured as a list in cgmon.yaml (hub.telegram), bots: ') + h.tg_list; };
			o.depends('hub_enabled', '1');
		} else {
			o = s.taboption('hub', form.Value, 'tg_bot', _('Telegram: bot token'),
				h.tg_bot_set ? _('Set. Empty — keep it.') : _('From @BotFather, like 123456789:AA…'));
			o.password = true;
			o.depends('hub_enabled', '1');
			o = s.taboption('hub', form.Value, 'tg_chat', _('Telegram: chat'), _('Chat or user id to send failures to (find it via @userinfobot).'));
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
					throw new Error(_('Passwords do not match'));
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
				ui.addNotification(null, E('p', _('No changes')), 'info');
				return;
			}
			return fs.exec(BIN, [ 'luci-set', JSON.stringify(p) ]).then(function(res) {
				var out = {};
				try { out = JSON.parse(res.stdout || '{}'); } catch (e) {}
				if (res.code !== 0 || out.error)
					throw new Error(out.error || res.stderr || ('code ' + res.code));
				ui.addNotification(null, E('p', _('Saved, cgmon restarted')), 'info');
				window.setTimeout(function() { location.reload(); }, 2500);
			});
		}).catch(function(e) {
			ui.addNotification(null, E('p', _('Not saved: ') + (e.message || e)), 'error');
		});
	},

	handleSave: null,
	handleReset: null
});
