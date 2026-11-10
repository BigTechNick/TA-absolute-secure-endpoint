/* SPDX-License-Identifier: Apache-2.0 - Copyright 2026 Nikhil Chawla */
/*
 * TA-absolute-secure-endpoint - Inputs page.
 * Absolute accounts (API host, token ID, secret key, optional proxy): add, edit, test, delete.
 * Inputs (SIEM events, devices): add, edit, enable/disable, run now, delete.
 * Talks to /services/absolute_se/inputs and /services/absolute_se/accounts.
 */
require([
    'jquery',
    'splunkjs/mvc',
    'splunkjs/mvc/searchmanager',
    'splunkjs/mvc/simplexml/ready!'
], function ($, mvc, SearchManager) {
    'use strict';

    var APP = 'TA-absolute-secure-endpoint';
    var service = mvc.createService({ owner: 'nobody', app: APP });
    var state = { inputs: [], accounts: [], accountNames: [], indexes: [], status: {} };
    var $root = $('#absolute-inputs-app');
    var KINDS = {
        events: { label: 'SIEM events', interval: '300', sourcetype: 'absolute:events' },
        devices: { label: 'Devices', interval: '86400', sourcetype: 'absolute:devices' }
    };
    var API_HOSTS = ['api.absolute.com'];
    var PERIPHERALS = 'printers,usbs,keyboards,pointingDevices,sounds,cameras,cdRoms,displays';

    // ------------------------------------------------------------ REST

    function parse(resp) {
        var data = resp && resp.data !== undefined ? resp.data : resp;
        if (typeof data === 'string') {
            try { data = JSON.parse(data); } catch (e) { /* keep text */ }
        }
        return data || {};
    }

    function errorText(err) {
        var data = parse(err);
        if (data && data.error) { return data.error; }
        if (data && data.messages && data.messages.length) { return data.messages[0].text; }
        return 'Request failed' + (err && err.status ? ' (HTTP ' + err.status + ')' : '');
    }

    function api(method, path, params, done, fail) {
        var url = '/services/absolute_se/' + path;
        var args = $.extend({ output_mode: 'json' }, params || {});
        var cb = function (err, resp) {
            if (err) { (fail || showError)(errorText(err)); return; }
            done(parse(resp));
        };
        if (method === 'GET') { service.get(url, args, cb); } else { service.post(url, args, cb); }
    }

    // ------------------------------------------------------------ helpers

    function el(tag, attrs, children) {
        var $e = $('<' + tag + '>');
        $.each(attrs || {}, function (k, v) {
            if (k === 'text') { $e.text(v); } else if (k === 'class') { $e.addClass(v); } else { $e.attr(k, v); }
        });
        $.each(children || [], function (_, c) { if (c) { $e.append(c); } });
        return $e;
    }

    function button(label, cls, onClick) {
        return el('button', { type: 'button', 'class': 'btn ' + (cls || ''), text: label }).on('click', onClick);
    }

    function flash(text, cls) {
        var $m = $root.find('.abs-flash');
        $m.removeClass('abs-error abs-ok').addClass(cls || 'abs-ok').text(text).show();
        if (cls !== 'abs-error') { setTimeout(function () { $m.fadeOut(); }, 8000); }
    }

    function showError(text) { flash(text, 'abs-error'); }

    function fmtTime(epoch) {
        if (!epoch) { return ''; }
        return new Date(epoch * 1000).toLocaleString();
    }

    function field(label, $input, help) {
        return el('div', { 'class': 'abs-field' }, [
            el('label', { text: label }), $input, help ? el('div', { 'class': 'abs-help', text: help }) : null
        ]);
    }

    function textInput(name, value, placeholder) {
        return el('input', { type: 'text', name: name, value: value || '', placeholder: placeholder || '' });
    }

    function select(name, options, value) {
        var $s = el('select', { name: name });
        $.each(options, function (_, o) {
            var opt = typeof o === 'string' ? { value: o, label: o } : o;
            $s.append(el('option', { value: opt.value, text: opt.label }));
        });
        $s.val(value);
        return $s;
    }

    function modal(title, $body, submitLabel, onSubmit) {
        var $overlay = el('div', { 'class': 'abs-overlay' });
        var $msg = el('div', { 'class': 'abs-form-error' }).hide();
        var close = function () { $overlay.remove(); };
        var $submit = button(submitLabel, 'btn-primary', function () {
            $msg.hide();
            $submit.prop('disabled', true);
            onSubmit(function (err) {
                $submit.prop('disabled', false);
                if (err) { $msg.text(err).show(); } else { close(); }
            });
        });
        var $box = el('div', { 'class': 'abs-modal' }, [
            el('h3', { text: title }), $body, $msg,
            el('div', { 'class': 'abs-modal-buttons' }, [button('Cancel', '', close), $submit])
        ]);
        $overlay.append($box).appendTo('body');
        $box.find('input:visible').first().trigger('focus');
        return $box;
    }

    // ------------------------------------------------------------ live status

    var statusSearch = new SearchManager({
        id: 'absolute_input_status',
        search: 'index=_internal sourcetype="absolute:ta:log" ("run done" OR "run failed" OR "run stopped") ' +
            '| rex field=source "absolute_se_(?<input_kind>events|devices)_(?<input>[^/]+?)\\.log(?:\\.\\d+)?$" ' +
            '| rex "^\\S+ \\S+ (?<log_level>[A-Z]+) run (?<result>done|failed|stopped): (?<detail>.*)$" ' +
            '| rex field=detail "behind (?<behind>-?[\\d.]+) min" ' +
            '| stats latest(_time) as last_run latest(result) as result latest(detail) as detail ' +
            'latest(behind) as behind by input_kind input',
        earliest_time: '-25h',
        latest_time: 'now',
        autostart: false,
        preview: false,
        cache: false
    });
    statusSearch.data('results', { count: 0 }).on('data', function (results) {
        var data = results.data();
        var idx = {};
        $.each(data.fields, function (i, f) { idx[f] = i; });
        // Indexed logs (search heads, or forwarders that index locally). The input's own
        // log file on this instance wins when it is newer.
        $.each(data.rows, function (_, row) {
            var key = row[idx.input_kind] + '/' + row[idx.input];
            var found = {
                last_run: parseFloat(row[idx.last_run]),
                result: row[idx.result],
                detail: row[idx.detail],
                behind: row[idx.behind]
            };
            var local = state.status[key];
            if (!local || !local.last_run || local.last_run < found.last_run) { state.status[key] = found; }
        });
        renderInputs();
    });

    function liveStatus(item) {
        if (item.disabled) { return el('span', { 'class': 'abs-badge abs-off', text: 'Disabled' }); }
        var s = state.status[item.kind + '/' + item.name];
        if (!s || !s.last_run) {
            return el('span', { 'class': 'abs-badge abs-wait', text: 'Enabled - no run logged yet' });
        }
        var age = (Date.now() / 1000) - s.last_run;
        var late = item.kind === 'events' ? 1800 : 93600;
        var cls = 'abs-good';
        var label = 'OK';
        if (s.result === 'failed') { cls = 'abs-bad'; label = 'Last run failed'; }
        else if (s.result === 'stopped') { cls = 'abs-wait'; label = 'Last run stopped'; }
        else if (age > late) { cls = 'abs-warn'; label = 'Late'; }
        else if (s.behind && parseFloat(s.behind) > 60) { cls = 'abs-warn'; label = 'Behind'; }
        var $wrap = el('div', {}, [
            el('span', { 'class': 'abs-badge ' + cls, text: label }),
            el('div', { 'class': 'abs-sub', text: 'Last run ' + fmtTime(s.last_run) })
        ]);
        if (s.detail) {
            $wrap.append(el('div', { 'class': 'abs-sub' + (s.result === 'failed' ? ' abs-errtext' : ''),
                text: s.detail }));
        }
        return $wrap;
    }

    // ------------------------------------------------------------ load

    function load() {
        api('GET', 'inputs', {}, function (data) {
            state.inputs = data.inputs || [];
            state.accountNames = data.accounts || [];
            state.indexes = data.indexes || [];
            state.status = {};
            $.each(state.inputs, function (_, item) {   // from this instance's log files
                if (item.status && item.status.last_run) { state.status[item.kind + '/' + item.name] = item.status; }
            });
            renderInputs();
            statusSearch.startSearch();
        });
        loadAccounts();
    }

    function loadAccounts() {
        api('GET', 'accounts', {}, function (data) {
            state.accounts = data.accounts || [];
            renderAccounts();
        });
    }

    // ------------------------------------------------------------ inputs table

    function settingsText(item) {
        if (item.kind === 'events') {
            var parts = ['first run ' + (item.start_hours_ago || '24') + ' h back',
                'delay ' + (item.delay_minutes || '5') + ' min', 'overlap ' + (item.overlap_minutes || '10') + ' min'];
            if (item.exclude_event_types) { parts.push('leaving out ' + item.exclude_event_types); }
            return parts.join(', ');
        }
        var hours = item.connected_within_hours === '' || item.connected_within_hours === undefined
            ? '24' : item.connected_within_hours;
        var out = [hours === '0' ? 'every device' : 'connected within ' + hours + ' h',
            'page size ' + (item.page_size || '100')];
        if (item.exclude_fields) { out.push('leaving out ' + item.exclude_fields); }
        return out.join(', ');
    }

    function scheduleText(item) {
        var iv = item.interval || KINDS[item.kind].interval;
        var every = /^\d+$/.test(iv) ? (iv % 3600 === 0 ? (iv / 3600) + ' h' : iv % 60 === 0 ? (iv / 60) + ' min'
            : iv + ' s') : 'cron ' + iv;
        return 'every ' + every + ' to ' + (item.index || 'default');
    }

    function renderInputs() {
        var $tb = $root.find('#abs-input-rows').empty();
        if (!state.inputs.length) {
            $tb.append(el('tr', {}, [el('td', { colspan: 6, 'class': 'abs-empty',
                text: 'No inputs yet. Save an Absolute account below, then add an input.' })]));
            return;
        }
        $.each(state.inputs, function (_, item) {
            var actions = el('div', { 'class': 'abs-actions' }, [
                button('Edit', 'btn-small', function () { inputForm(item); }),
                button(item.disabled ? 'Enable' : 'Disable', 'btn-small', function () {
                    inputAction(item.disabled ? 'enable' : 'disable', item);
                }),
                item.disabled ? null : button('Run now', 'btn-small', function () { inputAction('run', item); }),
                button('Delete', 'btn-small abs-danger', function () {
                    if (window.confirm('Delete input "' + item.name + '"? Events already indexed stay; ' +
                            'its checkpoint is removed, so an input created again with this name starts over.')) {
                        inputAction('delete', item);
                    }
                })
            ]);
            $tb.append(el('tr', {}, [
                el('td', {}, [el('strong', { text: item.name }),
                    el('div', { 'class': 'abs-sub', text: KINDS[item.kind].label })]),
                el('td', { text: item.account }),
                el('td', {}, [el('div', { text: scheduleText(item) }),
                    el('div', { 'class': 'abs-sub', text: 'sourcetype ' + KINDS[item.kind].sourcetype })]),
                el('td', { 'class': 'abs-sub', text: settingsText(item) }),
                el('td', {}, [liveStatus(item)]),
                el('td', {}, [actions])
            ]));
        });
    }

    function inputAction(action, item) {
        api('POST', 'inputs', { action: action, kind: item.kind, name: item.name }, function (data) {
            state.inputs = data.inputs || [];
            renderInputs();
            loadAccounts();
            var done = { run: 'started', enable: 'enabled', disable: 'disabled', 'delete': 'deleted' }[action];
            flash('Input ' + item.name + ' ' + (done || action) + '.');
            if (action !== 'delete') { setTimeout(function () { statusSearch.startSearch(); }, 8000); }
        });
    }

    // ------------------------------------------------------------ input form

    function inputForm(item) {
        var editing = !!item;
        item = item || {};
        if (!state.accountNames.length) {
            showError('Save an Absolute account first (Absolute accounts, below).');
            return;
        }
        var kind = item.kind || 'events';
        var $index = textInput('index', item.index === 'default' ? '' : (item.index || ''), 'default');
        $index.attr({ list: 'abs-index-list', autocomplete: 'off' });
        var $indexList = el('datalist', { id: 'abs-index-list' });
        $.each(state.indexes, function (_, name) { $indexList.append(el('option', { value: name })); });
        var $interval = textInput('interval', item.interval || KINDS[kind].interval, KINDS[kind].interval);

        var $events = el('div', { 'class': 'abs-kind-events' }, [
            field('First run: hours back', textInput('start_hours_ago', item.start_hours_ago, '24'),
                'How far back the first run starts (0-720; 0 = from now on). Later runs continue from the checkpoint.'),
            field('Leave out event types', textInput('exclude_event_types', item.exclude_event_types,
                'e.g. ApplicationUpdated'), 'Comma-separated eventType names not to index. Empty = all.')
        ]);
        var $excludeFields = textInput('exclude_fields', item.exclude_fields, 'none');
        var $devices = el('div', { 'class': 'abs-kind-devices' }, [
            field('Devices connected within (hours)', textInput('connected_within_hours', item.connected_within_hours, '24'),
                'Only devices that connected to Absolute in the last N hours. 0 = every device in the account, ' +
                'retired ones included.'),
            field('Leave out fields', el('div', {}, [$excludeFields,
                el('a', { href: '#', 'class': 'abs-toggle', text: 'Leave out peripherals' }).on('click', function (e) {
                    e.preventDefault(); $excludeFields.val(PERIPHERALS);
                })]), 'Comma-separated top-level fields of the device record not to index, to save license.')
        ]);
        var $advEvents = el('div', { 'class': 'abs-kind-events' }, [
            field('Delay (minutes)', textInput('delay_minutes', item.delay_minutes, '5'),
                'Each window ends this long before now, so Absolute has finished recording its events.'),
            field('Overlap (minutes)', textInput('overlap_minutes', item.overlap_minutes, '10'),
                'Each window starts this long before the previous one ended; events already sent are skipped by id.'),
            field('Page size', textInput('page_size', item.kind === 'events' ? item.page_size : '', '1000'),
                'Events per API call (1-1000).')
        ]);
        var $advDevices = el('div', { 'class': 'abs-kind-devices' }, [
            field('Page size', textInput('page_size_devices', item.kind === 'devices' ? item.page_size : '', '100'),
                'Devices per API call (1-1000; 0 = the API default of 10).')
        ]);
        var $adv = el('div', { 'class': 'abs-advanced' }, [$advEvents, $advDevices,
            field('Log level', select('log_level', ['INFO', 'DEBUG', 'WARNING', 'ERROR'],
                (item.log_level || 'INFO').toUpperCase()))
        ]).hide();
        var $kind = editing ? el('div', { 'class': 'abs-static', text: KINDS[kind].label })
            : select('kind', [{ value: 'events', label: 'SIEM events (device, console and alert activity)' },
                { value: 'devices', label: 'Devices (inventory snapshot)' }], kind);
        var showKind = function (k) {
            $body.find('.abs-kind-events').toggle(k === 'events');
            $body.find('.abs-kind-devices').toggle(k === 'devices');
        };
        var $body = el('div', { 'class': 'abs-form' }, [
            field('Type', $kind),
            editing ? field('Name', el('div', { 'class': 'abs-static', text: item.name }))
                : field('Name', textInput('name', '', 'e.g. absolute-events'),
                    'Letters, digits, . _ - (used in log and checkpoint file names)'),
            field('Absolute account', select('account', state.accountNames, item.account || state.accountNames[0]),
                'The events\' host field is the account name.'),
            field('Index', el('div', {}, [$index, $indexList]),
                'Any index name; it does not have to exist on this forwarder (empty = default).'),
            field('Interval', $interval, 'Seconds between runs, or a cron schedule. Defaults: 300 for SIEM events, ' +
                '86400 (daily) for devices.'),
            $events, $devices,
            el('a', { href: '#', 'class': 'abs-toggle', text: 'Advanced settings' }).on('click', function (e) {
                e.preventDefault(); $adv.toggle();
            }),
            $adv
        ]);
        if (!editing) {
            $kind.on('change', function () {
                showKind(this.value);
                var other = this.value === 'events' ? 'devices' : 'events';
                if (!$interval.val() || $interval.val() === KINDS[other].interval) {
                    $interval.val(KINDS[this.value].interval);
                }
            });
        }
        modal(editing ? 'Edit input ' + item.name : 'Add input', $body, editing ? 'Save' : 'Add', function (done) {
            var k = editing ? kind : $kind.val();
            var params = { action: editing ? 'edit' : 'create', kind: k,
                name: editing ? item.name : String($body.find('[name=name]').val() || '').trim() };
            var scope = $body.find('.abs-field').filter(function () {
                var $kindBox = $(this).closest('.abs-kind-events, .abs-kind-devices');
                return !$kindBox.length || $kindBox.hasClass('abs-kind-' + k);
            });
            scope.find('input[type=text], select').each(function () {
                var n = $(this).attr('name');
                var v = String($(this).val() || '').trim();
                // new inputs: empty settings are left to the defaults; edits: empty resets to the default
                if (n && n !== 'name' && n !== 'kind' && (editing || v !== '')) { params[n] = v; }
            });
            if (params.page_size_devices !== undefined) {
                params.page_size = params.page_size_devices;
                delete params.page_size_devices;
            }
            if (!params.index) { params.index = 'default'; }
            api('POST', 'inputs', params, function (data) {
                state.inputs = data.inputs || [];
                renderInputs();
                loadAccounts();
                flash(editing ? 'Input ' + item.name + ' saved; it runs again with the new settings.'
                    : 'Input ' + params.name + ' added; its first run starts within a minute.');
                setTimeout(function () { statusSearch.startSearch(); }, 10000);
                done();
            }, done);
        });
        showKind(kind);
    }

    // ------------------------------------------------------------ accounts

    function renderAccounts() {
        var $tb = $root.find('#abs-account-rows').empty();
        if (!state.accounts.length) {
            $tb.append(el('tr', {}, [el('td', { colspan: 6, 'class': 'abs-empty',
                text: 'No Absolute accounts. In the Absolute console, create an API token (Settings > API ' +
                    'management) with read access to SIEM events and devices, then add it here.' })]));
            return;
        }
        $.each(state.accounts, function (_, a) {
            $tb.append(el('tr', {}, [
                el('td', {}, [el('strong', { text: a.name })]),
                el('td', { text: a.error || a.api_host || '' }),
                el('td', { text: a.token_id_hint || '' }),
                el('td', { text: a.proxy_url || '-' }),
                el('td', { text: (a.used_by || []).join(', ') || '-' }),
                el('td', {}, [el('div', { 'class': 'abs-actions' }, [
                    button('Test', 'btn-small', function () { testAccount(a.name); }),
                    button('Edit', 'btn-small', function () { accountForm(a); }),
                    button('Delete', 'btn-small abs-danger', function () {
                        if (window.confirm('Delete Absolute account "' + a.name + '"?')) {
                            api('POST', 'accounts', { action: 'delete', name: a.name }, function () {
                                flash('Account ' + a.name + ' deleted.');
                                load();
                            });
                        }
                    })
                ])])
            ]));
        });
    }

    function testAccount(name) {
        flash('Testing ' + name + '...');
        api('POST', 'accounts', { action: 'test', name: name }, function (data) {
            var checks = data.checks || {};
            var parts = $.map(checks, function (v, k) {
                return (k === 'siem_events' ? 'SIEM events' : k === 'devices' ? 'Devices' : k) + ': ' + v;
            });
            flash('Account ' + name + ' (' + (data.api_host || '') + '): ' + parts.join('; '),
                data.ok ? 'abs-ok' : 'abs-error');
        });
    }

    function accountForm(account) {
        var editing = !!account;
        account = account || {};
        var $host = textInput('api_host', account.api_host || 'api.absolute.com', 'api.absolute.com');
        $host.attr({ list: 'abs-host-list', autocomplete: 'off' });
        var $hostList = el('datalist', { id: 'abs-host-list' });
        $.each(API_HOSTS, function (_, h) { $hostList.append(el('option', { value: h })); });
        var $body = el('div', { 'class': 'abs-form' }, [
            editing ? field('Name', el('div', { 'class': 'abs-static', text: account.name }))
                : field('Name', textInput('name', '', 'e.g. absolute'),
                    'Letters, digits, . _ - . Stored as the host field of the events collected with it.'),
            field('API host', el('div', {}, [$host, $hostList]),
                'api.absolute.com, or the regional API host that matches the Absolute console you sign in to ' +
                '(api.<region>.absolute.com).'),
            field('Token ID', textInput('token_id', '', editing ? 'unchanged (' + (account.token_id_hint || '') + ')'
                : 'the API token ID')),
            field('Secret key', el('input', { type: 'password', name: 'token_secret', autocomplete: 'new-password',
                placeholder: editing ? 'unchanged' : 'the API token secret key' })),
            field('Proxy (optional)', textInput('proxy_url', account.proxy_url || '',
                'http(s) URL of the proxy, with host and port'),
                'Only when this forwarder reaches the internet through a proxy. Without it, the proxy in ' +
                'splunkd\'s environment (https_proxy) is used, if set.'),
            el('div', { 'class': 'abs-help', text: 'The token ID and secret key are stored encrypted in ' +
                'Splunk\'s credential store; the secret key is never shown again.' })
        ]);
        modal(editing ? 'Edit account ' + account.name : 'Add Absolute account', $body, 'Save', function (done) {
            var params = { action: 'save',
                name: editing ? account.name : String($body.find('[name=name]').val() || '').trim() };
            $body.find('input').each(function () {
                var n = $(this).attr('name');
                if (n && n !== 'name') { params[n] = String($(this).val() || '').trim(); }
            });
            api('POST', 'accounts', params, function () {
                flash('Account ' + params.name + ' saved.');
                load();
                done();
                testAccount(params.name);
            }, done);
        });
    }

    // ------------------------------------------------------------ page

    $root.empty().append(
        el('div', { 'class': 'abs-flash' }).hide(),
        el('div', { 'class': 'abs-section' }, [
            el('div', { 'class': 'abs-head' }, [
                el('h2', { text: 'Inputs' }),
                el('div', {}, [
                    button('Refresh', '', load),
                    button('Add input', 'btn-primary', function () { inputForm(null); })
                ])
            ]),
            el('p', { 'class': 'abs-help', text: 'SIEM events: device, console and alert activity, collected ' +
                'every few minutes from a checkpoint (sourcetype absolute:events). Devices: an inventory ' +
                'snapshot, daily by default (sourcetype absolute:devices). Each input runs on this forwarder ' +
                'on its interval; host = the account name.' }),
            el('table', { 'class': 'table table-striped abs-table' }, [
                el('thead', {}, [el('tr', {}, $.map(['Name', 'Account', 'Schedule and index', 'Settings',
                    'Status', ''], function (h) { return el('th', { text: h }); }))]),
                el('tbody', { id: 'abs-input-rows' })
            ])
        ]),
        el('div', { 'class': 'abs-section' }, [
            el('div', { 'class': 'abs-head' }, [
                el('h2', { text: 'Absolute accounts' }),
                button('Add account', 'btn-primary', function () { accountForm(null); })
            ]),
            el('table', { 'class': 'table table-striped abs-table' }, [
                el('thead', {}, [el('tr', {}, $.map(['Name', 'API host', 'Token ID', 'Proxy', 'Used by', ''],
                    function (h) { return el('th', { text: h }); }))]),
                el('tbody', { id: 'abs-account-rows' })
            ])
        ])
    );
    load();
});
