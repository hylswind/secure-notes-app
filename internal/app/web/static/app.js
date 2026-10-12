(function () {
  'use strict';
  function $(id) { return document.getElementById(id); }
  var state = { view: 'notes', q: '', tag: '', page: 1, pageSize: 50, total: 0, note: null, dirty: false, timer: null, saving: false };

  function api(method, path, body) {
    var opt = { method: method, headers: {} };
    if (body !== undefined) { opt.headers['Content-Type'] = 'application/json'; opt.body = JSON.stringify(body); }
    return fetch(path, opt).then(function (r) {
      if (r.status === 401) { location.href = '/'; throw new Error('unauthorized'); }
      if (r.status === 204) { return { status: 204, data: null }; }
      return r.json().then(function (d) { return { status: r.status, data: d }; });
    });
  }

  function setMessage(text, withReload) {
    var m = $('message');
    m.textContent = '';
    if (!text) { m.hidden = true; return; }
    m.hidden = false;
    m.appendChild(document.createTextNode(text + ' '));
    if (withReload) {
      var b = document.createElement('button');
      b.type = 'button'; b.className = 'button'; b.textContent = 'Reload their version';
      b.addEventListener('click', function () { state.dirty = false; openNote(state.note.id); });
      m.appendChild(b);
    }
  }

  function listPath() {
    var p = state.view === 'shared' ? '/api/shared' : '/api/notes';
    var q = ['page=' + state.page, 'page_size=' + state.pageSize];
    if (state.q) q.push('q=' + encodeURIComponent(state.q));
    if (state.tag) q.push('tag=' + encodeURIComponent(state.tag));
    if (state.view === 'trash') q.push('trash=1');
    return p + '?' + q.join('&');
  }

  function loadList() {
    return api('GET', listPath()).then(function (r) {
      var ul = $('note-list');
      ul.textContent = '';
      var tags = {};
      r.data.notes.forEach(function (n) {
        (n.tags || []).forEach(function (t) { tags[t] = true; });
        var li = document.createElement('li');
        var b = document.createElement('button');
        b.type = 'button';
        if (state.note && state.note.id === n.id) b.setAttribute('aria-current', 'true');
        var t = document.createElement('span'); t.className = 't'; t.textContent = n.title;
        var s = document.createElement('span'); s.className = 's'; s.textContent = n.snippet || '';
        b.appendChild(t); b.appendChild(s);
        b.addEventListener('click', function () { confirmLeave(function () { openNote(n.id); }); });
        li.appendChild(b); ul.appendChild(li);
      });
      if (!r.data.notes.length) {
        var e = document.createElement('li'); e.className = 'muted'; e.textContent = 'No notes.'; ul.appendChild(e);
      }
      state.total = r.data.total;
      var pages = Math.max(1, Math.ceil(r.data.total / state.pageSize));
      $('page-info').textContent = state.page + ' / ' + pages;
      $('prev').disabled = state.page <= 1;
      $('next').disabled = state.page >= pages;
      renderChips(Object.keys(tags).sort());
    });
  }

  function renderChips(tags) {
    var c = $('tag-chips');
    c.textContent = '';
    if (state.tag && tags.indexOf(state.tag) < 0) tags.push(state.tag);
    tags.forEach(function (t) {
      var b = document.createElement('button');
      b.type = 'button'; b.className = 'chip' + (t === state.tag ? ' active' : '');
      b.setAttribute('aria-pressed', t === state.tag ? 'true' : 'false');
      b.textContent = t;
      b.addEventListener('click', function () { state.tag = state.tag === t ? '' : t; state.page = 1; loadList(); });
      c.appendChild(b);
    });
  }

  function confirmLeave(next) {
    if (state.dirty && !state.note.readOnly) { saveNow().then(next); } else { next(); }
  }

  function showEditor(n) {
    var trashed = !!n.deleted_at, ro = !n.owned || trashed;
    n.readOnly = ro;
    state.note = n; state.dirty = false;
    $('empty').hidden = true; $('note-form').hidden = false;
    $('title').value = n.title; $('tags').value = (n.tags || []).join(', '); $('body').value = n.body || '';
    ['title', 'tags', 'body'].forEach(function (id) { $(id).readOnly = ro; });
    $('save').hidden = ro; $('share').hidden = ro;
    $('trash').hidden = ro; $('restore').hidden = !(n.owned && trashed); $('delete-forever').hidden = !(n.owned && trashed);
    $('save-state').textContent = n.owned ? '' : 'Shared by ' + (n.owner_email || 'someone') + ' (read-only)';
    setMessage('');
    preview();
  }

  function openNote(id) {
    return api('GET', '/api/notes/' + encodeURIComponent(id)).then(function (r) {
      if (r.status !== 200) { setMessage(r.data.error || 'Could not load note'); return; }
      showEditor(r.data);
      loadList();
    });
  }

  function preview() { $('preview').innerHTML = window.renderMarkdown($('body').value); }

  function parseTags() {
    return $('tags').value.split(',').map(function (t) { return t.trim().toLowerCase(); }).filter(function (t) { return t; });
  }

  function saveNow() {
    clearTimeout(state.timer);
    if (!state.note || state.note.readOnly || state.saving) { return Promise.resolve(); }
    state.saving = true;
    $('save-state').textContent = 'Saving…';
    var n = state.note;
    return api('PUT', '/api/notes/' + encodeURIComponent(n.id), {
      title: $('title').value, body: $('body').value, tags: parseTags(), updated_at: n.updated_at
    }).then(function (r) {
      state.saving = false;
      if (r.status === 200) {
        n.updated_at = r.data.updated_at; n.title = r.data.title;
        state.dirty = false; setMessage(''); $('save-state').textContent = 'Saved';
        return loadList();
      }
      if (r.status === 409) {
        $('save-state').textContent = '';
        setMessage('This note was changed elsewhere since you opened it.', true);
        return;
      }
      $('save-state').textContent = '';
      setMessage(r.data.error || 'Save failed');
    }, function () { state.saving = false; });
  }

  function changed() {
    if (!state.note || state.note.readOnly) return;
    state.dirty = true; $('save-state').textContent = 'Unsaved changes';
    clearTimeout(state.timer);
    state.timer = setTimeout(saveNow, 2000);
  }

  function setView(v) {
    confirmLeave(function () {
      state.view = v; state.page = 1; state.tag = '';
      ['notes', 'shared', 'trash'].forEach(function (x) {
        $('view-' + x).classList.toggle('active', x === v);
        $('view-' + x).setAttribute('aria-selected', x === v ? 'true' : 'false');
      });
      loadList();
    });
  }

  $('view-notes').addEventListener('click', function () { setView('notes'); });
  $('view-shared').addEventListener('click', function () { setView('shared'); });
  $('view-trash').addEventListener('click', function () { setView('trash'); });
  $('prev').addEventListener('click', function () { state.page--; loadList(); });
  $('next').addEventListener('click', function () { state.page++; loadList(); });
  var searchTimer;
  $('search').addEventListener('input', function () {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(function () { state.q = $('search').value.trim(); state.page = 1; loadList(); }, 250);
  });
  $('new-note').addEventListener('click', function () {
    confirmLeave(function () {
      api('POST', '/api/notes', { title: 'Untitled', body: '', tags: [] }).then(function (r) {
        if (r.status === 201) { setView('notes'); showEditor(r.data); $('title').focus(); $('title').select(); }
      });
    });
  });
  ['title', 'tags', 'body'].forEach(function (id) { $(id).addEventListener('input', changed); });
  $('body').addEventListener('input', preview);
  $('note-form').addEventListener('submit', function (e) { e.preventDefault(); saveNow(); });
  $('trash').addEventListener('click', function () {
    api('DELETE', '/api/notes/' + encodeURIComponent(state.note.id)).then(function () { clearEditor(); loadList(); });
  });
  $('restore').addEventListener('click', function () {
    api('POST', '/api/notes/' + encodeURIComponent(state.note.id) + '/restore').then(function () { clearEditor(); loadList(); });
  });
  $('delete-forever').addEventListener('click', function () {
    if (!confirm('Delete this note permanently? This cannot be undone.')) return;
    api('DELETE', '/api/notes/' + encodeURIComponent(state.note.id) + '?permanent=1').then(function () { clearEditor(); loadList(); });
  });
  function clearEditor() { state.note = null; state.dirty = false; $('note-form').hidden = true; $('empty').hidden = false; }

  // sharing
  var dlg = $('share-dialog');
  function loadShares() {
    return api('GET', '/api/notes/' + encodeURIComponent(state.note.id) + '/shares').then(function (r) {
      var ul = $('share-list'); ul.textContent = '';
      (r.data || []).forEach(function (s) {
        var li = document.createElement('li');
        li.appendChild(document.createTextNode(s.email + ' '));
        var b = document.createElement('button');
        b.type = 'button'; b.className = 'button'; b.textContent = 'Revoke';
        b.setAttribute('aria-label', 'Revoke ' + s.email);
        b.addEventListener('click', function () {
          api('DELETE', '/api/notes/' + encodeURIComponent(state.note.id) + '/shares/' + encodeURIComponent(s.email)).then(loadShares);
        });
        li.appendChild(b); ul.appendChild(li);
      });
    });
  }
  $('share').addEventListener('click', function () {
    $('share-error').hidden = true; $('share-email').value = '';
    loadShares().then(function () { if (dlg.showModal) dlg.showModal(); else dlg.setAttribute('open', ''); $('share-email').focus(); });
  });
  $('share-close').addEventListener('click', function () { if (dlg.close) dlg.close(); else dlg.removeAttribute('open'); });
  $('share-form').addEventListener('submit', function (e) {
    e.preventDefault();
    api('POST', '/api/notes/' + encodeURIComponent(state.note.id) + '/shares', { email: $('share-email').value }).then(function (r) {
      if (r.status === 201) { $('share-error').hidden = true; $('share-email').value = ''; loadShares(); }
      else { $('share-error').hidden = false; $('share-error').textContent = r.data.error || 'Could not share'; }
    });
  });

  window.addEventListener('beforeunload', function (e) { if (state.dirty) { e.preventDefault(); e.returnValue = ''; } });
  loadList();
})();
