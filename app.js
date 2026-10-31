// portgas crew — the brothers' page.
//
// They see the board and the desk the Mac publishes, and suggest bets. Each
// suggestion is signed with a key this browser makes and can't export; the
// Mac shows it to its owner and places nothing until he approves it.
//
// Joining: the Mac makes an invite with a code for one named brother. This
// page sends the public half of its key with an HMAC of it keyed by that
// code, the same proof the phone uses, and waits for the Mac to accept it.

(() => {
  "use strict";

  const cfg = window.CREW_CONFIG || {};
  const API = (cfg.supabaseURL || "").replace(/\/$/, "") + "/rest/v1/";
  const KEY = cfg.anonKey || "";
  // The cloud signer serves the board with the Mac off: the Mac's last one,
  // with Polymarket's prices and scores laid over it.
  const CLOUD = (cfg.cloudURL || "https://portgas-signer.vercel.app").replace(/\/$/, "");

  const $ = (id) => document.getElementById(id);
  const main = $("main");

  const state = {
    me: loadMe(),            // { macID, name, publicKey }
    tab: "matches",
    league: "all",
    query: "",
    board: null, boardAt: null,
    macAt: null,             // when the Mac itself last published
    desk: null, deskAt: null,
    picks: [],
    lastStatus: {},          // suggestion id → status, for "it was placed" toasts
    sheet: null,             // { match, index, stake, note }
    matchID: null,           // the match page that's open, from #m=<id>
    charts: {},              // match id → { range, series, at, loading, error }
    events: {},              // slug → Polymarket event, for tokens and volume
    view: pref("crew.view", "compact"),    // compact | timeline | leagues
    stars: new Set(pref("crew.stars", [])),
    onlyStars: false,
    feed: [], feedAt: 0,     // the whole crew's picks, newest first
    members: {}, membersAt: 0,             // public key → { name, avatar }
    deskAccount: null,       // the account the desk's bets are narrowed to
  };

  // MARK: Storage

  /// A setting this browser keeps for itself: the view, the stars.
  function pref(name, fallback) {
    try { const v = localStorage.getItem(name); return v == null ? fallback : JSON.parse(v); } catch { return fallback; }
  }
  function setPref(name, value) {
    try { localStorage.setItem(name, JSON.stringify(value)); } catch {}
  }

  function loadMe() {
    try { return JSON.parse(localStorage.getItem("crew.me") || "null"); } catch { return null; }
  }
  function saveMe(me) {
    state.me = me;
    try { localStorage.setItem("crew.me", JSON.stringify(me)); } catch {}
  }

  function idb() {
    return new Promise((resolve, reject) => {
      const open = indexedDB.open("portgas-crew", 1);
      open.onupgradeneeded = () => open.result.createObjectStore("keys");
      open.onsuccess = () => resolve(open.result);
      open.onerror = () => reject(open.error);
    });
  }
  async function keyGet(name) {
    const db = await idb();
    return new Promise((resolve, reject) => {
      const r = db.transaction("keys").objectStore("keys").get(name);
      r.onsuccess = () => resolve(r.result || null);
      r.onerror = () => reject(r.error);
    });
  }
  async function keyPut(name, value) {
    const db = await idb();
    return new Promise((resolve, reject) => {
      const tx = db.transaction("keys", "readwrite");
      tx.objectStore("keys").put(value, name);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  }

  // MARK: Crypto

  const utf8 = (s) => new TextEncoder().encode(s);
  const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));

  /// This browser's key: made once, kept in IndexedDB, never exportable.
  async function myKey() {
    let pair = await keyGet("me");
    if (!pair) {
      pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
      await keyPut("me", pair);
    }
    const raw = await crypto.subtle.exportKey("raw", pair.publicKey);
    return { pair, publicKey: b64(raw) };
  }

  /// HMAC of the public key, keyed by the code: proof it was read off the Mac.
  async function proof(code, publicKey) {
    const k = await crypto.subtle.importKey("raw", utf8(code.toUpperCase()), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    return b64(await crypto.subtle.sign("HMAC", k, utf8(publicKey)));
  }

  async function sign(text) {
    const { pair } = await myKey();
    return b64(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, pair.privateKey, utf8(text)));
  }

  /// This browser's key for receiving the desk key: the desk is published
  /// sealed, and the Mac wraps the key to this. Signed with the key above
  /// when it's handed over, so nobody can swap theirs in.
  async function myBox() {
    let pair = await keyGet("box");
    if (!pair) {
      pair = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
      await keyPut("box", pair);
    }
    const publicKey = b64(await crypto.subtle.exportKey("raw", pair.publicKey));
    return { pair, publicKey, sig: await sign(publicKey) };
  }

  const b64d = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

  async function aesOpen(key, sealed) {
    const d = b64d(sealed);
    return crypto.subtle.decrypt({ name: "AES-GCM", iv: d.slice(0, 12) }, key, d.slice(12));
  }

  /// The desk key from its wrapped copy: ECDH with the Mac's one-off key,
  /// HKDF-SHA256, then AES-GCM. The same steps as the Mac's DeskSeal.
  async function unwrapDeskKey(wrapped) {
    const { pair } = await myBox();
    const epk = await crypto.subtle.importKey("raw", b64d(wrapped.epk), { name: "ECDH", namedCurve: "P-256" }, false, []);
    const bits = await crypto.subtle.deriveBits({ name: "ECDH", public: epk }, pair.privateKey, 256);
    const hk = await crypto.subtle.importKey("raw", bits, "HKDF", false, ["deriveKey"]);
    const wrapping = await crypto.subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt: utf8("portgas desk v1"), info: new Uint8Array() },
      hk, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
    return crypto.subtle.importKey("raw", await aesOpen(wrapping, wrapped.box), "AES-GCM", false, ["decrypt"]);
  }

  let deskKey = null;
  async function openDesk(doc) {
    if (!doc?.sealed) return doc || null;
    const read = async () => JSON.parse(new TextDecoder().decode(await aesOpen(deskKey, doc.sealed)));
    if (deskKey) { try { return await read(); } catch { deskKey = null; } }
    const row = await one("crew_keys?select=wrapped&reader=" + eq(state.me.publicKey));
    if (!row) return null;
    deskKey = await unwrapDeskKey(row.wrapped);
    return read();
  }

  /// Hands the Mac this browser's box key, once, for browsers that joined
  /// before there was one.
  async function registerBox() {
    const { publicKey, sig } = await myBox();
    if (localStorage.getItem("crew.box") === publicKey) return;
    await api("crew_pairings?public_key=" + eq(state.me.publicKey), {
      method: "PATCH", headers: { Prefer: "return=minimal" },
      body: JSON.stringify({ box_key: publicKey, box_sig: sig }),
    });
    try { localStorage.setItem("crew.box", publicKey); } catch {}
  }

  // MARK: Supabase

  async function api(path, opts = {}) {
    const res = await fetch(API + path, {
      ...opts,
      headers: { apikey: KEY, Authorization: "Bearer " + KEY, "Content-Type": "application/json", ...(opts.headers || {}) },
    });
    if (!res.ok) throw new Error((await res.text()) || "HTTP " + res.status);
    const text = await res.text();
    return text ? JSON.parse(text) : null;
  }
  const eq = (v) => "eq." + encodeURIComponent(v);
  const one = async (path) => (await api(path))?.[0] || null;

  // MARK: Joining

  function inviteFromLink() {
    return inviteFrom(location.hash);
  }

  /// An invite from anything with `code=` in it: the link, or just its # part.
  function inviteFrom(text) {
    const hash = String(text || "").split("#").pop();
    const p = new URLSearchParams(hash);
    const code = cleanCode(p.get("code"));
    return code ? { code, mac: p.get("mac") || "", name: p.get("name") || "" } : null;
  }

  /// A code as people paste it: the Mac shows it spaced, "A B C D 2 3 4 5",
  /// and phones capitalise or add stray characters. Only letters and digits
  /// count.
  function cleanCode(text) {
    return String(text || "").toUpperCase().replace(/[^A-Z0-9]/g, "");
  }

  function renderJoin(invite, message, isError) {
    $("tabs").hidden = true;
    main.innerHTML = `
      <div class="join">
        <h1>${invite?.name ? "Hey " + esc(invite.name) + "." : "Join the desk."}</h1>
        <p>See every match and the desk live, and suggest bets. Nothing you suggest is placed until it's approved.</p>
        ${invite?.code ? "" : `
          <label for="code">Invite code</label>
          <input id="code" class="code" autocomplete="off" autocapitalize="characters" spellcheck="false" placeholder="Paste the link or code">`}
        <button class="go" id="joinBtn">${invite?.code ? "Join" : "Join with this code"}</button>
        <p class="note ${isError ? "err" : ""}" id="joinNote">${esc(message || "")}</p>
      </div>`;
    $("joinBtn").onclick = () => join(invite);
    // Whatever he pastes — the whole link, or the code with its spaces — is
    // read for him, and a whole one joins without another tap.
    const field = $("code");
    if (field) field.oninput = () => {
      const fromLink = inviteFrom(field.value);
      if (fromLink) { renderJoin(fromLink); join(fromLink); return; }
      const code = cleanCode(field.value);
      if (field.value !== code) field.value = code;
      if (code.length === 8) join(null);
    };
  }

  let joining = false;

  async function join(invite) {
    if (joining) return;
    const code = cleanCode(invite?.code || $("code")?.value);
    const note = (t, bad) => { const n = $("joinNote"); if (n) { n.textContent = t; n.classList.toggle("err", !!bad); } };
    if (code.length !== 8) return note("The code is eight characters.", true);
    if (!crypto?.subtle) return note("This browser can't make a key. Open the link in Safari or Chrome.", true);
    $("joinBtn").disabled = true;
    joining = true;
    try {
      let mac = invite?.mac;
      if (!mac) {
        const seen = await one("device_state?select=device_id&order=last_seen.desc&limit=1");
        mac = seen?.device_id;
      }
      if (!mac) throw new Error("Can't see the Mac. Is portgas open on it?");
      const { publicKey } = await myKey();
      const box = await myBox();
      await api("crew_pairings", {
        method: "POST",
        headers: { Prefer: "resolution=merge-duplicates,return=minimal" },
        body: JSON.stringify({ public_key: publicKey, device_id: mac, proof: await proof(code, publicKey), approved: false,
                               box_key: box.publicKey, box_sig: box.sig }),
      });
      note("Waiting for the Mac to let you in…");
      for (let i = 0; i < 40; i++) {
        await sleep(2000);
        const row = await one("crew_pairings?select=approved,member_name&public_key=" + eq(publicKey));
        if (row?.approved) {
          saveMe({ macID: mac, name: row.member_name || invite?.name || "", publicKey });
          try { localStorage.setItem("crew.box", box.publicKey); } catch {}
          history.replaceState(null, "", location.pathname);
          start();
          return;
        }
      }
      throw new Error("The Mac didn't let you in. Check portgas is open on it and the code is still good (a day, one use).");
    } catch (e) {
      note(e.message || String(e), true);
      $("joinBtn").disabled = false;
    } finally {
      joining = false;
    }
  }

  // MARK: Reading

  async function refresh() {
    const mac = state.me.macID;
    const [cloud, board, desk, picks, mine] = await Promise.allSettled([
      fetch(CLOUD + "/board?mac=" + encodeURIComponent(mac)).then((r) => r.ok ? r.json() : null),
      one("crew_boards?select=doc,updated_at&device_id=" + eq(mac)),
      one("desk_snapshots?select=doc,updated_at&device_id=" + eq(mac)),
      api("crew_suggestions?select=id,status,detail,payload,created_at,handled_at&order=created_at.desc&limit=50&public_key=" + eq(state.me.publicKey)),
      one("crew_pairings?select=member_name,max_stake,daily_limit,alert_topic&public_key=" + eq(state.me.publicKey)),
    ]);
    if (cloud.status === "fulfilled" && cloud.value?.doc) {
      state.board = cloud.value.doc;
      state.boardAt = new Date(cloud.value.at);
      state.macAt = new Date(cloud.value.macAt);
    } else if (board.status === "fulfilled" && board.value) {
      state.board = board.value.doc;
      state.boardAt = state.macAt = new Date(board.value.updated_at);
    }
    if (desk.status === "fulfilled" && desk.value) {
      try {
        const opened = await openDesk(desk.value.doc);
        state.deskLocked = !opened;
        if (opened) { state.desk = opened; state.deskAt = new Date(desk.value.updated_at); }
      } catch { state.deskLocked = true; }
    }
    if (mine.status === "fulfilled" && mine.value) state.meRow = mine.value;
    if (picks.status === "fulfilled" && picks.value) {
      state.picks = picks.value.map((r) => ({ ...r, p: safeJSON(r.payload) }));
      announce();
    }
    render();
    // The crew's picks and faces change slowly: read again every so often,
    // and sooner while the Crew tab is open.
    const now = Date.now(), due = [];
    if (now - state.membersAt > 60000) due.push(readMembers());
    if (now - state.feedAt > (state.tab === "crew" ? 8000 : 30000)) due.push(readFeed());
    if (due.length) { await Promise.allSettled(due); render(); }
  }

  /// Everyone the Mac let in, with their pictures. Without the avatar column
  /// (its migration not run yet) the names still come through.
  async function readMembers() {
    const q = "&approved=is.true&device_id=" + eq(state.me.macID);
    let rows;
    // After a miss, the column is asked for again only every ten minutes.
    const tryAvatars = state.avatarsOK !== false || Date.now() - (state.avatarsMissAt || 0) > 600000;
    try {
      if (!tryAvatars) throw new Error("no avatar column");
      rows = await api("crew_pairings?select=public_key,member_name,avatar" + q);
      state.avatarsOK = true;
    } catch {
      rows = await api("crew_pairings?select=public_key,member_name" + q);
      if (tryAvatars) state.avatarsMissAt = Date.now();
      state.avatarsOK = false;
    }
    state.members = Object.fromEntries((rows || []).map((r) => [r.public_key, { name: r.member_name || "Crew", avatar: goodAvatar(r.avatar) }]));
    state.membersAt = Date.now();
  }

  /// The crew's picks to this Mac, each checked against its signer's key:
  /// the table is open, so a row nobody in the crew signed is left out.
  async function readFeed() {
    const rows = await api("crew_suggestions?select=id,public_key,status,detail,payload,signature,created_at,handled_at" +
      "&order=created_at.desc&limit=60&status=neq.refused&device_id=" + eq(state.me.macID));
    const checked = await Promise.all((rows || []).map(async (r) => (await signedBy(r)) ? { ...r, p: safeJSON(r.payload) } : null));
    state.feed = checked.filter((r) => r?.p);
    state.feedAt = Date.now();
  }

  const verified = {};
  async function signedBy(r) {
    if (r.id in verified) return verified[r.id];
    try {
      const k = await crypto.subtle.importKey("raw", b64d(r.public_key), { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
      verified[r.id] = await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, k, b64d(r.signature), utf8(r.payload));
    } catch { verified[r.id] = false; }
    return verified[r.id];
  }

  /// A toast when one of his picks gets an answer.
  function announce() {
    for (const r of state.picks) {
      const before = state.lastStatus[r.id];
      if (before === "pending" && r.status !== "pending" && r.status !== "withdrawn") {
        const what = pickName(r.p);
        if (r.status === "placed") { toast(`Approved: ${what}. ${r.detail || ""}`); buzz([30, 40, 30]); }
        else if (r.status === "declined") toast(`Not this time: ${what}.`, true);
        else toast(`${what}: ${r.detail || r.status}`, true);
        if (document.hidden) notify(r.status === "placed" ? `Approved: ${what}` : r.status === "declined" ? `Declined: ${what}` : what, r.detail || "");
      }
      state.lastStatus[r.id] = r.status;
    }
  }

  // MARK: Drawing

  // A redraw between a finger going down and coming up eats the tap, so one
  // that lands then waits for the finger to lift.
  let pressing = false, owed = false;
  document.addEventListener("pointerdown", () => { pressing = true; }, true);
  const lift = () => { pressing = false; if (owed) { owed = false; setTimeout(render, 0); } };
  document.addEventListener("pointerup", lift, true);
  document.addEventListener("pointercancel", lift, true);

  function render() {
    if (pressing) { owed = true; return; }
    renderStatus();
    const pending = state.picks.filter((r) => r.status === "pending").length;
    $("picksBadge").hidden = !pending;
    $("picksBadge").textContent = pending;
    document.querySelectorAll("#tabs button").forEach((b) => b.classList.toggle("on", b.dataset.tab === state.tab));
    if (state.matchID) return renderMatchPage();
    // The search, views and filters stay put once drawn: a redraw would take
    // the focus from the search box and scroll the league chips back.
    if (state.tab === "matches" && main.dataset.page === "list" && main.dataset.leagues === leaguesOnBoard().join("|")) return renderMatchList();
    delete main.dataset.page;
    if (state.tab === "matches") renderMatches();
    else if (state.tab === "crew") renderCrew();
    else if (state.tab === "picks") renderPicks();
    else renderDesk();
  }

  function renderStatus() {
    const since = (t) => t ? (Date.now() - t) / 1000 : Infinity;
    const macOn = since(state.macAt) < 45;
    // The Mac asleep with the cloud keeping the board live: prices and scores
    // are fresh, the desk is the Mac's last word, and picks go to the phone.
    const cloudOn = !macOn && since(state.boardAt) < 60;
    const text = `<span class="dot ${macOn || cloudOn ? "on" : ""}"></span>${
      macOn ? "live"
        : cloudOn ? "live · Mac asleep " + ago(state.macAt)
        : state.boardAt ? "desk asleep · " + ago(state.boardAt) : "waiting for the desk"}`;
    // His face, which opens his profile; drawn once so a refresh doesn't eat
    // the tap.
    const el = $("status");
    if (!el.querySelector(".me")) {
      el.innerHTML = `<span class="st"></span><button class="me" aria-label="Your profile"></button>`;
      el.querySelector(".me").onclick = openProfile;
    }
    el.querySelector(".st").innerHTML = text;
    const face = avatar(state.me.publicKey, "sm");
    const me = el.querySelector(".me");
    if (me.dataset.face !== face) { me.dataset.face = face; me.innerHTML = face; }
  }

  /// Tells the owner's phone about a pick when the Mac isn't up to. The
  /// signer checks the pick's signature and pushes each one once; plain
  /// text, so the browser sends it without asking first.
  function ping(id) {
    fetch(CLOUD, { method: "POST", headers: { "Content-Type": "text/plain" }, body: JSON.stringify({ crewNotify: id }) }).catch(() => {});
  }

  function matchesShown() {
    const ms = (state.board?.matches || []).filter((m) => !m.finished);
    const q = state.query.trim().toLowerCase();
    return ms.filter((m) => (state.league === "all" || m.league === state.league)
        && (!state.onlyStars || state.stars.has(m.id))
        && (!q || [m.home, m.away, m.league || ""].some((s) => s.toLowerCase().includes(q))));
  }

  const VIEWS = { timeline: "Timeline", compact: "Compact", leagues: "Leagues" };

  /// The board's leagues, the busiest first, for the filter chips.
  function leaguesOnBoard() {
    return Object.entries(
      (state.board?.matches || []).reduce((a, m) => { if (m.league) a[m.league] = (a[m.league] || 0) + 1; return a; }, {}))
      .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).map(([l]) => l);
  }

  function renderMatches() {
    const leagues = leaguesOnBoard();
    main.innerHTML = `
      <input id="search" class="search" placeholder="Team or league" value="${esc(state.query)}" autocomplete="off">
      <div class="viewbar">
        <div class="seg" role="tablist">${Object.entries(VIEWS).map(([k, v]) => `<button data-view="${k}" class="${state.view === k ? "on" : ""}">${v}</button>`).join("")}</div>
        <button class="starchip ${state.onlyStars ? "on" : ""}" id="onlyStars" aria-pressed="${state.onlyStars}">★ ${state.stars.size || ""}</button>
      </div>
      <div class="filters">
        ${["all", ...leagues].map((l) => `<button class="chip ${state.league === l ? "on" : ""}" data-league="${esc(l)}">${l === "all" ? "All" : esc(l)}</button>`).join("")}
      </div>
      <div id="list" class="view-${state.view}"></div>`;
    main.dataset.page = "list";
    main.dataset.leagues = leagues.join("|");
    $("search").oninput = (e) => { state.query = e.target.value; renderMatchList(); };
    main.querySelectorAll("[data-league]").forEach((b) => b.onclick = () => { state.league = b.dataset.league; renderMatches(); });
    main.querySelectorAll("[data-view]").forEach((b) => b.onclick = () => { state.view = b.dataset.view; setPref("crew.view", state.view); renderMatches(); });
    $("onlyStars").onclick = () => { state.onlyStars = !state.onlyStars; renderMatches(); };
    renderMatchList();
  }

  /// The list in the view he chose: a timeline of each day by kickoff, a
  /// compact line a match, or grouped by league. Live matches and starred
  /// ones come first in all three.
  function renderMatchList() {
    const list = $("list");
    if (!list) return;
    if (!state.board) { list.innerHTML = `<p class="empty">Waiting for the desk to publish the board…</p>`; return; }
    const ms = matchesShown();
    const byTime = (a, b) => new Date(a.kickoff) - new Date(b.kickoff);
    const live = ms.filter((m) => m.live);
    const starred = ms.filter((m) => !m.live && state.stars.has(m.id)).sort(byTime);
    const rest = ms.filter((m) => !m.live && !(state.stars.has(m.id) && !state.onlyStars)).sort(byTime);
    const row = state.view === "compact" ? compactRow : (m) => matchCard(m, state.view === "leagues" || !!m.live);
    let html = state.query || state.onlyStars ? "" : betsStrip();
    if (!ms.length) html += `<p class="empty">${state.onlyStars ? "No starred matches. Tap ☆ on a match to keep it up here." : "No matches with markets right now."}</p>`;
    if (live.length) html += section("Live now", live.length, "live") + live.map(row).join("");
    if (starred.length && !state.onlyStars) html += section("★ Starred", starred.length, "starred") + starred.map((m) => matchCard(m, true)).join("");
    if (state.view === "leagues") {
      const groups = {};
      for (const m of rest) (groups[m.league || "Other"] ||= []).push(m);
      for (const [league, items] of Object.entries(groups).sort((a, b) => b[1].length - a[1].length))
        html += section(league, items.length) + items.map((m) => matchCard(m, true)).join("");
    } else {
      const days = {};
      for (const m of rest) (days[dayLabel(m.kickoff)] ||= []).push(m);
      for (const [day, items] of Object.entries(days)) {
        html += section(day, items.length);
        if (state.view === "compact") { html += items.map(compactRow).join(""); continue; }
        // One stop on the timeline for each kickoff time, its matches beside it.
        const slots = {};
        for (const m of items) (slots[timeLabel(m.kickoff)] ||= []).push(m);
        html += `<div class="timeline">${Object.entries(slots).map(([t, group]) => `
          <div class="slot">
            <div class="rail"><span class="t">${t}</span><span class="until">${esc(untilShort(group[0].kickoff))}</span></div>
            <div class="slot-body">${group.map((m) => matchCard(m, false)).join("")}</div>
          </div>`).join("")}</div>`;
      }
    }
    // Only when something on it changed: the list is long, and a redraw
    // under a finger or mid-scroll loses the place.
    if (list.dataset.sig === html) return;
    list.dataset.sig = html;
    list.innerHTML = html;
    list.querySelectorAll("[data-pick]").forEach((b) => b.onclick = () => {
      const [id, i] = b.dataset.pick.split(":").map(Number);
      openSheet(id, i);
    });
    list.querySelectorAll("[data-star]").forEach((b) => b.onclick = (e) => { e.preventDefault(); toggleStar(Number(b.dataset.star)); renderMatchList(); });
  }

  function toggleStar(id) {
    if (state.stars.has(id)) state.stars.delete(id); else state.stars.add(id);
    setPref("crew.stars", [...state.stars]);
    const chip = $("onlyStars");
    if (chip) chip.textContent = "★ " + (state.stars.size || "");
  }

  const starButton = (m) => `<button class="star ${state.stars.has(m.id) ? "on" : ""}" data-star="${m.id}" aria-label="${state.stars.has(m.id) ? "Unstar" : "Star"} this match">${state.stars.has(m.id) ? "★" : "☆"}</button>`;

  const section = (title, n, cls = "") => `<div class="section-title ${cls}"><span>${esc(title)}</span><span>${n}</span></div>`;

  /// The desk's open bets, first thing on Matches, as the Mac's bet strip.
  function betsStrip() {
    const bets = state.desk?.bets || [];
    if (!bets.length) return "";
    const moved = bets.reduce((a, b) => a + (b.worth - b.stake), 0);
    const staked = bets.reduce((a, b) => a + b.stake, 0);
    return section(`${bets.length} open · ${money(staked)} in`, signed(moved)) +
      `<div class="strip">${bets.map(betCard).join("")}</div>`;
  }

  function betCard(b) {
    const mv = b.worth - b.stake;
    return `
      <a class="betcard ${mv > 0.005 ? "win" : mv < -0.005 ? "lose" : ""}" href="${b.matchID ? "#m=" + b.matchID : "#"}">
        <div class="bc1">${crest(b.homeCrest)}${crest(b.awayCrest)}<span class="bclock ${b.clockLive ? "live" : ""}">${esc(b.clock || "")}</span></div>
        <div class="bcpick">${esc(b.pick)}</div>
        <div class="bcfx">${esc(b.homeName)} v ${esc(b.awayName)}</div>
        <div class="bc2"><span>${money(b.stake)} → ${money(b.worth)}</span><b class="${tone(mv)}">${signed(mv)}</b></div>
        <div class="bc3">${cents(b.entry)} → ${cents(b.now)}${b.isReal ? " · REAL" : ""}${b.accountName ? " · " + esc(b.accountName) : ""}</div>
      </a>`;
  }

  function betsOn(matchID) { return (state.desk?.bets || []).filter((b) => b.matchID === matchID); }

  /// The others' picks waiting on this match, for the tag on its card.
  function crewOn(matchID) {
    return state.feed.filter((r) => r.status === "pending" && r.p?.matchID === matchID
      && r.public_key !== state.me.publicKey && state.members[r.public_key]);
  }

  /// A match in full: kickoff and league on top, the two sides with their
  /// table place and the score, what each outcome costs, and under them the
  /// market's split as a bar, the favourite and the meetings.
  function matchCard(m, showTime) {
    const mine = state.picks.some((r) => r.status === "pending" && r.p?.matchID === m.id);
    const others = crewOn(m.id);
    const info = m.info || {};
    const bets = betsOn(m.id);
    const labels = [m.home, "Draw", m.away];
    const clock = m.live ? (m.minute != null ? m.minute + "'" : "LIVE") : showTime ? whenShort(m.kickoff) : "";
    const place = (pos, rank) => pos ? `<span class="place">${ordinal(pos)}</span>` : rank ? `<span class="place">#${rank}</span>` : "";
    const side = (name, url, goals, pos, rank) => `
      <span class="trow">${crest(url, "", name)}<span class="team">${esc(name)}</span>${place(pos, rank)}${m.live ? `<span class="goals">${goals ?? 0}</span>` : ""}</span>`;
    const ps = m.prices.map((p) => p ?? 0), total = ps.reduce((a, b) => a + b, 0);
    const fav = total ? ps.indexOf(Math.max(...ps)) : -1;
    const h2h = info.homeWins != null ? `H2H ${info.homeWins}W ${info.draws}D ${info.awayWins}L${info.last ? " · last " + info.last : ""}` : "";
    return `
      <div class="match ${bets.length ? "has-bet" : ""} ${m.live ? "is-live" : ""}">
        <div class="mmeta">
          ${clock ? `<span class="clock ${m.live ? "live" : ""}">${clock}</span>` : ""}
          <span class="league">${esc(m.league || "")}</span>
          ${mine ? `<span class="mine-tag">PICKED</span>` : ""}
          ${others.length ? `<span class="mine-tag crewtag">${faces(others.map((r) => r.public_key))}${others.length} CREW</span>` : ""}
          ${reading(m.id) ? `<span class="mine-tag model">MODEL</span>` : ""}
          <span class="mmeta-end">${polyLink(m.slug)}${starButton(m)}</span>
        </div>
        ${m.live && m.minute != null ? `<div class="progress" title="${m.minute}' of 90"><i style="width:${Math.min(100, (m.minute / 90) * 100).toFixed(1)}%"></i></div>` : ""}
        <div class="mbody">
          <a class="teams" href="#m=${m.id}">${side(m.home, m.homeCrest, m.homeGoals, info.homePosition, info.homeRank)}${side(m.away, m.awayCrest, m.awayGoals, info.awayPosition, info.awayRank)}</a>
          ${[0, 1, 2].map((i) => `
            <button class="price ${["home", "draw", "away"][i]} ${i === fav ? "fav" : ""}" data-pick="${m.id}:${i}" aria-label="${esc(labels[i])} ${cents(m.prices[i])}" ${m.prices[i] == null ? "disabled" : ""}>
              <span class="lbl">${["Home", "Draw", "Away"][i]}</span><span class="c">${cents(m.prices[i])}</span>
            </button>`).join("")}
        </div>
        ${total ? `
        <div class="mfoot">
          <div class="split" aria-hidden="true">${ps.map((p, i) => `<i class="${["home", "draw", "away"][i]}" style="flex:${p.toFixed(3)}"></i>`).join("")}</div>
          <div class="mfoot-text"><span><em>FAV</em> ${esc(labels[fav])} ${Math.round((ps[fav] / total) * 100)}%</span>${h2h ? `<span>${esc(h2h)}</span>` : ""}</div>
        </div>` : ""}
        ${bets.map((b) => { const mv = b.worth - b.stake; return `
          <a class="rowbet" href="#m=${m.id}"><span>Desk bet · <b>${esc(b.pick)}</b> · ${money(b.stake)} at ${cents(b.entry)}${b.isReal ? " · REAL" : ""}</span><span class="${tone(mv)}">${money(b.worth)} ${signed(mv)}</span></a>`; }).join("")}
      </div>`;
  }

  /// A match on one line, for scanning a busy day.
  function compactRow(m) {
    const bets = betsOn(m.id);
    const clock = m.live ? (m.minute != null ? m.minute + "'" : "LIVE") : timeLabel(m.kickoff);
    return `
      <div class="crow ${bets.length ? "has-bet" : ""}">
        ${starButton(m)}
        <span class="clock ${m.live ? "live" : ""}">${clock}</span>
        <a class="cteams" href="#m=${m.id}">
          <span class="ct">${crest(m.homeCrest, "", m.home)}<span class="team">${esc(m.home)}</span>${m.live ? `<b>${m.homeGoals ?? 0}</b>` : ""}</span>
          <span class="ct">${crest(m.awayCrest, "", m.away)}<span class="team">${esc(m.away)}</span>${m.live ? `<b>${m.awayGoals ?? 0}</b>` : ""}</span>
        </a>
        ${[0, 1, 2].map((i) => `<button class="cprice ${["home", "draw", "away"][i]}" data-pick="${m.id}:${i}" aria-label="${esc([m.home, "Draw", m.away][i])} ${cents(m.prices[i])}" ${m.prices[i] == null ? "disabled" : ""}>${cents(m.prices[i])}</button>`).join("")}
      </div>`;
  }

  // MARK: A match

  const RANGES = { "2h": "2h", "6h": "6h", "1d": "1d", "1w": "1w", max: "All" };
  const LINE = ["#f2f2f2", "#a3a3a3", "#7ea6ff"];

  /// The match page, laid out as the Mac's: the two sides with their table
  /// place and world rank, the meetings, the prices over time, three price
  /// tiles, and the model. Drawn once per match; each refresh updates the
  /// parts around the chart, so a finger on the chart isn't interrupted.
  function renderMatchPage() {
    const m = matchByID(state.matchID);
    if (!m) {
      delete main.dataset.page;
      main.innerHTML = `<p class="empty">That match isn't on the board any more.<br><br><a class="back" href="#">‹ Matches</a></p>`;
      return;
    }
    if (main.dataset.page !== "m" + m.id) {
      main.dataset.page = "m" + m.id;
      main.innerHTML = `
        <div class="mp">
          <div class="mp-top"><a class="back" href="#">‹ Matches</a>
            <div class="mp-actions"><button class="act" id="mStar"></button><button class="act" id="mShare">Share</button>${polyLink(m.slug, "pm big")}</div>
          </div>
          <div id="mHead"></div>
          <div id="mBets"></div>
          <div class="chartcard">
            <div class="chart-top"><span id="mTraded" class="kicker">Price</span><div class="ranges" id="mRanges"></div></div>
            <div class="chart" id="mChart"><p class="empty">Loading the chart…</p></div>
            <div class="legend" id="mLegend"></div>
          </div>
          <div class="tiles" id="mTiles"></div>
          <div class="bw" id="mModel"></div>
          <div id="mPicks"></div>
        </div>`;
      $("mShare").onclick = () => shareMatch(m);
      $("mStar").onclick = () => { toggleStar(m.id); drawStar(m); };
      loadChart(m);
    }
    drawStar(m);
    const info = m.info || {};
    const meta = (pos, rank) => [pos ? `${ordinal(pos)}<em> ${esc((m.league || "").toUpperCase())}</em>` : null, rank ? "#" + rank.toLocaleString() : null].filter(Boolean);
    const side = (name, url, colour, goals, pos, rank) => `
      <div class="side-row">
        ${crest(url, "big", name)}<i class="bar" style="background:${colour}"></i>
        <span class="side-name">${esc(name)}</span>
        ${m.live || m.finished ? `<span class="side-goals">${goals ?? 0}</span>` : ""}
        <span class="side-meta">${meta(pos, rank).map((x) => `<span>${x}</span>`).join("")}</span>
      </div>`;
    const h2h = info.homeWins != null ? `H2H ${info.homeWins}W ${info.draws}D ${info.awayWins}W${info.last ? " · LAST " + info.last : ""}` : "";
    $("mHead").innerHTML = `
      <div class="kicker head-kicker"><span>${esc(m.league || "")}</span><span class="${m.live ? "down" : ""}">${m.live
        ? (m.minute != null ? m.minute + "' · LIVE" : "LIVE")
        : esc(dayLabel(m.kickoff)) + " " + timeLabel(m.kickoff) + " · " + esc(untilLabel(m.kickoff))}</span></div>
      ${side(m.home, m.homeCrest, LINE[0], m.homeGoals, info.homePosition, info.homeRank)}
      ${side(m.away, m.awayCrest, LINE[2], m.awayGoals, info.awayPosition, info.awayRank)}
      ${h2h ? `<div class="kicker h2h">${esc(h2h)}</div>` : ""}`;

    // Built once and then only relabelled: a tile swapped out between a
    // finger going down and coming up never gets its tap.
    const tiles = $("mTiles");
    const names = [m.home, "Draw", m.away];
    if (!tiles.children.length) {
      tiles.innerHTML = [0, 1, 2].map((i) => `
        <button class="tile" data-pick="${m.id}:${i}">
          <div class="tile-top"><i class="sw ${i === 1 ? "hatch" : ""}" style="background:${i === 1 ? "" : LINE[i]}"></i>${i === 1 ? "" : crest(i === 0 ? m.homeCrest : m.awayCrest, "", names[i])}<span>${esc(names[i])}</span></div>
          <div class="tile-price"></div>
          <div class="tile-foot">tap to suggest</div>
        </button>`).join("");
      tiles.querySelectorAll("[data-pick]").forEach((b) => b.onclick = () => openSheet(m.id, Number(b.dataset.pick.split(":")[1])));
    }
    tiles.querySelectorAll("[data-pick]").forEach((b, i) => {
      b.disabled = m.prices[i] == null;
      b.querySelector(".tile-price").textContent = cents(m.prices[i]);
    });

    const r = reading(m.id);
    $("mModel").innerHTML = `<b>blackwood1</b><span>${r ? esc(r.note) : "Not reading this match. It reads live matches while Devil Mode runs."}</span>`;
    drawRanges(m);
    drawTraded(m);
    drawBets(m);
    const c = state.charts[m.id];
    if (c && !c.loading && Date.now() - (c.at || 0) > (m.live ? 20000 : 120000)) loadChart(m);
  }

  function ordinal(n) {
    const s = ["th", "st", "nd", "rd"], v = n % 100;
    return (n + (s[(v - 20) % 10] || s[v] || s[0])).toUpperCase();
  }

  function drawRanges(m) {
    const el = $("mRanges");
    if (!el) return;
    const current = state.charts[m.id]?.range;
    const sig = current || "";
    if (el.dataset.sig === sig) return;
    el.dataset.sig = sig;
    el.innerHTML = Object.keys(RANGES).map((k) => `<button class="rng ${current === k ? "on" : ""}" data-range="${k}">${RANGES[k]}</button>`).join("");
    el.querySelectorAll("[data-range]").forEach((b) => b.onclick = () => loadChart(m, b.dataset.range));
  }

  function drawTraded(m) {
    const ev = state.events[m.slug], el = $("mTraded");
    if (!el) return;
    const vol = Number(ev?.volume) || 0;
    el.textContent = ev ? `PRICE · ${short(vol)} TRADED · ${short(Number(ev.liquidity) || 0)} LIQUIDITY` : "PRICE";
  }

  function short(v) { return "$" + (v >= 1e6 ? (v / 1e6).toFixed(1) + "M" : v >= 1e3 ? (v / 1e3).toFixed(1) + "K" : Math.round(v)); }

  /// The desk's money on this match sits right under the sides, and his
  /// picks on it at the bottom.
  function drawBets(m) {
    const el = $("mBets"), pk = $("mPicks");
    if (!el || !pk) return;
    const bets = betsOn(m.id);
    el.innerHTML = bets.length ? section(bets.length === 1 ? "Your bet on this" : `Your ${bets.length} bets on this`, signed(bets.reduce((a, b) => a + b.worth - b.stake, 0))) + bets.map((b) => bet(b, false)).join("") : "";
    const picks = state.picks.filter((r) => r.p?.matchID === m.id && r.p?.kind !== "sell");
    const others = state.feed.filter((r) => r.p?.matchID === m.id && r.p?.kind !== "sell" && r.public_key !== state.me.publicKey && state.members[r.public_key]);
    const html = (picks.length ? section("Your picks here", picks.length) + picks.map((r) => `
      <div class="kv"><span>${esc(pickName(r.p))} · ${money(r.p.stake)} at ${cents(r.p.price)}</span><span class="kv-end">${withdrawButton(r)}${statusPill(r.status)}</span></div>`).join("") : "") +
      (others.length ? section("The crew on this", others.length) + others.map(feedRow).join("") : "");
    // Redrawn only when something in it changed, so a tap on Withdraw lands.
    if (pk.dataset.sig !== html) { pk.dataset.sig = html; pk.innerHTML = html; wirePicks(pk); }
    wireSells(el);
  }

  function drawStar(m) {
    const b = $("mStar");
    if (b) { const on = state.stars.has(m.id); b.textContent = on ? "★" : "☆"; b.setAttribute("aria-label", on ? "Unstar" : "Star"); b.classList.toggle("on", on); }
  }

  /// The match's link, to the group chat: the share sheet where there is
  /// one, else copied.
  async function shareMatch(m) {
    const url = location.origin + location.pathname + "#m=" + m.id;
    const text = `${m.home} v ${m.away} · ${whenShort(m.kickoff)} · ${[m.home, "Draw", m.away].map((n, i) => `${n} ${cents(m.prices[i])}`).join(" · ")}`;
    if (navigator.share) {
      try { await navigator.share({ title: `${m.home} v ${m.away}`, text, url }); return; }
      catch (e) { if (e.name === "AbortError") return; }
    }
    try { await navigator.clipboard.writeText(text + "\n" + url); toast("Link copied. Paste it in the chat."); }
    catch { prompt("Copy this link:", url); }
  }

  function reading(matchID) {
    return (state.desk?.devil?.readings || []).find((r) => r.matchID === matchID) || null;
  }

  function wireSells(el) {
    el.querySelectorAll("[data-sell]").forEach((b) => b.onclick = () => openSellSheet(b.dataset.sell));
  }

  // MARK: The chart

  /// The event, read again after a minute (fifteen seconds while live), so
  /// its volume and tokens stay current.
  async function eventFor(slug) {
    const cached = state.events[slug];
    if (cached && Date.now() - cached._at < (cached.live ? 15000 : 60000)) return cached;
    const res = await fetch("https://gamma-api.polymarket.com/events?slug=" + encodeURIComponent(slug));
    const ev = (await res.json())?.[0];
    if (!ev) throw new Error("Polymarket doesn't have this match any more.");
    ev._at = Date.now();
    state.events[slug] = ev;
    return ev;
  }

  /// The "yes" token of each of home, draw, away, the way the Mac picks them:
  /// the draw by name, and the two teams by the event title's "Home vs. Away".
  function yesTokens(ev) {
    const open = (ev.markets || []).filter((x) => x.closed !== true);
    const all = open.length >= 3 ? open : ev.markets || [];
    let pool = all.filter((x) => x.sportsMarketType === "moneyline");
    if (pool.length < 3) pool = all;
    const isDraw = (x) => (x.slug || "").endsWith("-draw") || (x.groupItemTitle || "").toLowerCase().startsWith("draw")
      || (x.question || "").toLowerCase().includes("end in a draw");
    const draw = pool.find(isDraw);
    const teams = pool.filter((x) => x !== draw);
    if (!draw || teams.length < 2) return null;
    const [h, a] = (ev.title || "").split(/\s+vs\.?\s+/i);
    const best = (list, name) => list.reduce((b, x) => (likeness(x.groupItemTitle || x.question, name) > likeness(b.groupItemTitle || b.question, name) ? x : b), list[0]);
    const home = h ? best(teams, h) : teams[0];
    const rest = teams.filter((x) => x !== home);
    const away = a ? best(rest, a) : rest[0];
    const token = (x) => { try { return JSON.parse(x.clobTokenIds)[0]; } catch { return null; } };
    const tokens = [token(home), token(draw), token(away)];
    return tokens.every(Boolean) ? tokens : null;
  }

  function likeness(a, b) {
    const words = (s) => String(s || "").toLowerCase().normalize("NFD").replace(/[^a-z0-9 ]/g, " ").split(/\s+/).filter((w) => w.length > 2);
    const x = words(a), y = new Set(words(b));
    return x.filter((w) => y.has(w)).length / Math.max(1, Math.max(x.length, y.size));
  }

  function rangeQuery(range) {
    const now = Math.floor(Date.now() / 1000);
    return {
      "2h": `startTs=${now - 7200}&endTs=${now}&fidelity=1`,
      "6h": `startTs=${now - 21600}&endTs=${now}&fidelity=2`,
      "1d": "interval=1d&fidelity=5",
      "1w": "interval=1w&fidelity=60",
      max: "interval=max&fidelity=360",
    }[range];
  }

  async function loadChart(m, range) {
    range ||= state.charts[m.id]?.range || (m.live ? "2h" : "1d");
    const c = { ...(state.charts[m.id] || {}), range, loading: true };
    state.charts[m.id] = c;
    drawRanges(m);
    try {
      const ev = await eventFor(m.slug);
      drawTraded(m);
      const tokens = yesTokens(ev);
      if (!tokens) throw new Error("This match has no home/draw/away market to chart.");
      const q = rangeQuery(range);
      c.series = await Promise.all(tokens.map((t) =>
        fetch(`https://clob.polymarket.com/prices-history?market=${t}&${q}`).then((r) => r.json()).then((j) => j.history || [])));
      c.error = null;
    } catch (e) {
      c.error = e.message || String(e);
    }
    c.loading = false;
    c.at = Date.now();
    if (state.charts[m.id] === c && state.matchID === m.id) drawChart(m);
  }

  /// The prices over time, drawn as the Mac draws them: 0–100¢ on the
  /// right, kickoff marked, the home line shaded, and a readout of all three
  /// at the moment under the finger.
  function drawChart(m) {
    const el = $("mChart"), c = state.charts[m.id];
    if (!el || !c) return;
    if (c.error) { el.innerHTML = `<p class="empty">${esc(c.error)}</p>`; return; }
    const series = c.series || [];
    const all = series.flat();
    if (!all.length) { el.innerHTML = `<p class="empty">No trades in this range yet.</p>`; legend(m, null); return; }
    const W = Math.max(280, el.clientWidth), H = el.clientHeight || 260;
    const L = 4, R = 46, T = 14, B = 22;
    const t0 = Math.min(...all.map((d) => d.t)), t1 = Math.max(...all.map((d) => d.t));
    const span = Math.max(1, t1 - t0);
    const x = (t) => L + ((t - t0) / span) * (W - L - R);
    const y = (p) => T + (1 - p) * (H - T - B);
    const ko = new Date(m.kickoff) / 1000;
    const tick = (t) => new Date(t * 1000).toLocaleString([], span > 36 * 3600 ? { day: "numeric", month: "short" } : { hour: "2-digit", minute: "2-digit" });
    let svg = `<svg width="${W}" height="${H}" viewBox="0 0 ${W} ${H}">`;
    for (let g = 0; g <= 1.0001; g += 0.2) svg += `<line x1="${L}" x2="${W - R}" y1="${y(g)}" y2="${y(g)}" class="grid"/><text x="${W - 4}" y="${y(g) + 4}" class="axis" text-anchor="end">${Math.round(g * 100)}¢</text>`;
    for (let i = 0; i <= 3; i++) { const t = t0 + (span * i) / 3; svg += `<text x="${x(t)}" y="${H - 5}" class="axis" text-anchor="${i === 0 ? "start" : i === 3 ? "end" : "middle"}">${tick(t)}</text>`; }
    if (t0 < ko) svg += `<text x="${L + 12}" y="${T + 16}" class="phase">PRE-MATCH</text>`;
    if (ko > t0 && ko < t1) {
      svg += `<line x1="${x(ko)}" x2="${x(ko)}" y1="${T}" y2="${H - B}" class="ko"/>` +
        `<g transform="translate(${Math.min(x(ko) + 6, W - R - 92)},${T + 2})"><rect width="88" height="18" class="ko-pill"/><text x="8" y="13" class="ko-text">▶ KICKOFF 0'</text></g>`;
    }
    for (const g of m.goals || []) {
      const t = new Date(g.at) / 1000;
      if (t < t0 || t > t1) continue;
      svg += `<line x1="${x(t)}" x2="${x(t)}" y1="${T}" y2="${H - B}" class="goal" stroke="${LINE[g.side]}"/>` +
        `<text x="${x(t)}" y="${H - B - 6}" class="goal-label" text-anchor="middle">⚽${g.minute != null ? " " + g.minute + "'" : ""}</text>`;
    }
    const pts = (s) => s.map((d) => x(d.t).toFixed(1) + "," + y(d.p).toFixed(1)).join(" ");
    if (series[0]?.length) svg += `<polygon points="${x(series[0][0].t)},${y(0)} ${pts(series[0])} ${x(series[0][series[0].length - 1].t)},${y(0)}" class="area"/>`;
    series.forEach((s, i) => { if (s.length) svg += `<polyline points="${pts(s)}" fill="none" stroke="${LINE[i]}" stroke-width="${i === 1 ? 1.4 : 1.8}"/>`; });
    svg += `<line id="xhair" x1="0" x2="0" y1="${T}" y2="${H - B}" class="xhair" visibility="hidden"/>`;
    svg += [0, 1, 2].map((i) => `<circle id="dot${i}" r="5" fill="${LINE[i]}" stroke="#000" stroke-width="1.5" visibility="hidden"/>`).join("") + `</svg>`;
    el.innerHTML = svg;

    const at = (s, t) => { let lo = 0, hi = s.length - 1; while (lo < hi) { const mid = (lo + hi + 1) >> 1; if (s[mid].t <= t) lo = mid; else hi = mid - 1; } return s[lo]; };
    const show = (t) => {
      const values = series.map((s) => (s.length ? at(s, t).p : null));
      legend(m, values, t);
      return values;
    };
    show(t1);
    const hair = $("xhair");
    const move = (ev) => {
      const r = el.getBoundingClientRect();
      const px = Math.min(W - R, Math.max(L, ev.clientX - r.left));
      const t = t0 + ((px - L) / (W - L - R)) * span;
      const values = show(t);
      hair.setAttribute("x1", px); hair.setAttribute("x2", px); hair.setAttribute("visibility", "visible");
      values.forEach((v, i) => { const d = $("dot" + i); if (v == null) return; d.setAttribute("cx", px); d.setAttribute("cy", y(v)); d.setAttribute("visibility", "visible"); });
    };
    const leave = () => { hair.setAttribute("visibility", "hidden"); [0, 1, 2].forEach((i) => $("dot" + i).setAttribute("visibility", "hidden")); show(t1); };
    el.onpointermove = move; el.onpointerdown = move; el.onpointerleave = leave; el.onpointerup = (e) => { if (e.pointerType !== "mouse") leave(); };
  }

  /// Under the chart: each side at the moment shown, and when that was —
  /// the match minute once it's under way.
  function legend(m, values, t) {
    const el = $("mLegend");
    if (!el) return;
    const names = [m.home, "Draw", m.away];
    const ko = new Date(m.kickoff) / 1000;
    // The match minute: the clock's own at the latest point, else time since
    // kickoff less the fifteen-minute break once it's past the first half.
    const elapsed = t ? Math.round((t - ko) / 60) : 0;
    const minute = m.live && m.minute != null && Date.now() / 1000 - t < 120 ? m.minute
      : elapsed > 60 ? Math.max(45, elapsed - 15) : Math.min(45, elapsed);
    const when = t ? (t >= ko && t < ko + 3 * 3600 ? `at ${Math.max(0, minute)}' · ` : "") +
      new Date(t * 1000).toLocaleString([], { hour: "numeric", minute: "2-digit" }) : "";
    el.innerHTML = names.map((n, i) => `<span><i style="background:${LINE[i]}"></i>${esc(n)} <b style="color:${i === 2 ? LINE[2] : "var(--text)"}">${values?.[i] != null ? Math.round(values[i] * 100) + "¢" : "–"}</b></span>`).join("") +
      `<span class="when">${esc(when)}</span>`;
  }

  function untilLabel(iso) {
    const s = (new Date(iso) - Date.now()) / 1000;
    if (s <= 0) return "kicking off";
    if (s < 3600) return "in " + Math.round(s / 60) + " min";
    if (s < 86400) return "in " + Math.round(s / 3600) + " h";
    return "in " + Math.round(s / 86400) + " days";
  }

  function renderPicks() {
    const alerts = alertsBlock();
    if (!state.picks.length) {
      main.innerHTML = alerts + `<p class="empty">Nothing suggested yet. Tap a price on Matches.</p>`;
      wireAlerts();
      return;
    }
    const html = section("Your picks", state.picks.length) + state.picks.map((r) => {
      const p = r.p || {};
      const m = matchByID(p.matchID);
      return `
        <div class="pick-row">
          <div class="what"><span class="name">${esc(pickName(p))}</span>${statusPill(r.status)}</div>
          <div class="fx">${esc(fixtureOf(p))} · ${money(p.stake)} at ${cents(p.price)}${p.accountName ? " · into " + esc(p.accountName) : ""} · ${ago(new Date(r.created_at))}${polyLink(p.eventSlug || m?.slug, "pm inline")}</div>
          ${p.note ? `<div class="detail">“${esc(p.note)}”</div>` : ""}
          ${r.detail && r.status !== "pending" ? `<div class="detail">${esc(r.detail)}</div>` : ""}
          ${r.status === "pending" ? `<div class="pick-actions">${withdrawButton(r)}</div>` : ""}
        </div>`;
    }).join("") + alerts;
    // Redrawn only when something changed, so a tap on Withdraw lands.
    if (main.dataset.sig === html && main.querySelector(".pick-row")) return;
    main.dataset.sig = html;
    main.innerHTML = html;
    wirePicks(main);
    wireAlerts();
  }

  const STATUS = { pending: "waiting", placing: "placing", placed: "placed", declined: "declined", expired: "lapsed", refused: "refused", failed: "failed", kept: "not placed", withdrawn: "withdrawn" };
  const statusPill = (status) => `<span class="pill ${esc(status)}">${esc(STATUS[status] || status)}</span>`;

  /// Pulling a waiting pick back: a second tap within a few seconds does it.
  const withdrawButton = (r) => r.status === "pending" && (r.public_key == null || r.public_key === state.me.publicKey)
    ? `<button class="withdraw" data-withdraw="${esc(r.id)}">Withdraw</button>` : "";

  function wirePicks(el) {
    el.querySelectorAll("[data-withdraw]").forEach((b) => b.onclick = () => {
      if (b.dataset.armed) return withdraw(b.dataset.withdraw, b);
      b.dataset.armed = "1";
      b.textContent = "Tap again to withdraw";
      b.classList.add("armed");
      setTimeout(() => { if (b.isConnected && b.dataset.armed) { delete b.dataset.armed; b.textContent = "Withdraw"; b.classList.remove("armed"); } }, 3500);
    });
    el.querySelectorAll("[data-tail]").forEach((b) => b.onclick = () => {
      const r = state.feed.find((x) => x.id === b.dataset.tail);
      if (r) openSheet(r.p.matchID, r.p.outcomeIndex, r.p.side === "no" ? "no" : "yes");
    });
  }

  /// Marks his pick withdrawn, only while it's still waiting: one the owner
  /// is already placing stays his to finish. The Mac and the cloud signer
  /// pass over anything that isn't pending.
  async function withdraw(id, button) {
    button.disabled = true;
    button.textContent = "Withdrawing…";
    try {
      const rows = await api(`crew_suggestions?id=eq.${encodeURIComponent(id)}&status=eq.pending&public_key=` + eq(state.me.publicKey), {
        method: "PATCH", headers: { Prefer: "return=representation" },
        body: JSON.stringify({ status: "withdrawn", detail: `Withdrawn by ${state.me.name || "him"}.`, handled_at: new Date().toISOString() }),
      });
      const r = state.picks.find((x) => x.id === id);
      if (rows?.length) {
        if (r) { r.status = "withdrawn"; r.detail = rows[0].detail; }
        state.lastStatus[id] = "withdrawn";
        const f = state.feed.find((x) => x.id === id);
        if (f) f.status = "withdrawn";
        toast("Withdrawn. The owner won't see it.");
      } else {
        toast("Too late: it's already been answered.", true);
        refresh().catch(console.error);
      }
      render();
    } catch (e) {
      button.disabled = false;
      button.textContent = "Withdraw";
      toast("Couldn't withdraw: " + (e.message || e), true);
    }
  }

  // MARK: The crew

  /// Everyone in, with how their picks went, and the latest picks from all
  /// of them. A waiting or placed one can be backed again from here.
  function renderCrew() {
    const keys = Object.keys(state.members);
    const feed = state.feed.filter((r) => state.members[r.public_key]);
    const stats = (k) => {
      const mine = feed.filter((r) => r.public_key === k && r.p?.kind !== "sell");
      return { picks: mine.length, placed: mine.filter((r) => r.status === "placed").length, waiting: mine.filter((r) => r.status === "pending").length };
    };
    const members = keys.sort((a, b) => (b === state.me.publicKey) - (a === state.me.publicKey) || stats(b).picks - stats(a).picks);
    const html = section("The crew", keys.length) + `
      <div class="members">${members.map((k) => { const s = stats(k); return `
        <div class="member ${k === state.me.publicKey ? "me-card" : ""}">
          ${avatar(k, "lg")}
          <span class="mname">${esc(state.members[k].name)}${k === state.me.publicKey ? " (you)" : ""}</span>
          <span class="mstat">${s.picks} pick${s.picks === 1 ? "" : "s"} · ${s.placed} placed${s.waiting ? ` · <b>${s.waiting} waiting</b>` : ""}</span>
        </div>`; }).join("") || `<p class="empty">Nobody's in yet.</p>`}</div>
      ${state.avatarsOK === false ? `<p class="note">Pictures turn on once the owner runs the profile-picture update on the database.</p>` : ""}
      ${section("Latest picks", feed.length)}
      ${feed.map(feedRow).join("") || `<p class="empty">No picks yet.</p>`}`;
    if (main.dataset.sig === html && main.querySelector(".members")) return;
    main.dataset.sig = html;
    main.innerHTML = html;
    main.querySelectorAll(".member.me-card").forEach((b) => b.onclick = openProfile);
    wirePicks(main);
  }

  /// One of the crew's picks: who, what, how much, and how it went.
  function feedRow(r) {
    const p = r.p, who = state.members[r.public_key], m = matchByID(p.matchID);
    const isMe = r.public_key === state.me.publicKey;
    const canTail = !isMe && p.kind !== "sell" && m && !m.finished && (r.status === "pending" || r.status === "placed" || r.status === "placing");
    const what = p.kind === "sell" ? `says <b>${esc(pickName(p))}</b>` : `suggests <b>${esc(pickName(p))}</b>`;
    return `
      <div class="feed-row">
        ${avatar(r.public_key, "md")}
        <div class="feed-main">
          <div class="feed-top"><span><span class="who">${esc(isMe ? "You" : who?.name || "Crew")}</span> ${what}</span>${statusPill(r.status)}</div>
          <div class="fx">${m ? `<a href="#m=${m.id}">${esc(m.home)} v ${esc(m.away)}</a>` : esc(fixtureOf(p))} · ${money(p.stake)}${p.kind === "sell" ? "" : " at " + cents(p.price)}${p.accountName ? " · " + esc(p.accountName) : ""} · ${ago(new Date(r.created_at))}</div>
          ${p.note ? `<div class="detail">“${esc(p.note)}”</div>` : ""}
          ${canTail ? `<button class="tail" data-tail="${esc(r.id)}">Back it too · ${cents(p.side === "no" ? m.noPrices?.[p.outcomeIndex] : m.prices[p.outcomeIndex])}</button>` : ""}
          ${isMe ? withdrawButton(r) : ""}
        </div>
      </div>`;
  }

  // MARK: Faces

  /// A picture only if it's a small image of the kinds the page makes: the
  /// column is open, so anything else is dropped.
  function goodAvatar(s) {
    return typeof s === "string" && s.length < 80000 && /^data:image\/(jpeg|png|webp);base64,[A-Za-z0-9+/=]+$/.test(s) ? s : null;
  }

  /// His picture, else his initial on a colour of his own.
  function avatar(key, size = "md") {
    const who = state.members[key] || (key === state.me?.publicKey ? { name: state.me?.name } : null);
    const name = (who?.name || "?").trim();
    if (who?.avatar) return `<img class="av ${size}" src="${who.avatar}" alt="${esc(name)}">`;
    let h = 0;
    for (const c of String(key || "")) h = (h * 31 + c.charCodeAt(0)) >>> 0;
    return `<span class="av ${size} blank" style="--h:${h % 360}">${esc(name.charAt(0).toUpperCase())}</span>`;
  }

  const faces = (keys) => `<span class="faces">${[...new Set(keys)].slice(0, 3).map((k) => avatar(k, "xs")).join("")}</span>`;

  function openProfile() {
    const name = state.members[state.me.publicKey]?.name || state.me.name || "You";
    state.sheet = { profile: true };
    $("sheet").innerHTML = `
      <div class="kicker">Your profile</div>
      <div class="profile">
        ${avatar(state.me.publicKey, "xl")}
        <div><h2>${esc(name)}</h2><div class="sub">The crew sees this picture next to your picks.</div></div>
      </div>
      <label class="go filebtn">Choose a picture<input type="file" id="avatarFile" accept="image/*" hidden></label>
      ${state.members[state.me.publicKey]?.avatar ? `<button class="ghost" id="avatarRemove">Remove picture</button>` : ""}
      <button class="ghost" id="cancel">Done</button>`;
    $("cancel").onclick = closeSheet;
    $("avatarFile").onchange = async (e) => {
      const file = e.target.files?.[0];
      if (!file) return;
      try { await saveAvatar(await shrink(file)); } catch (err) { toast("Couldn't use that picture: " + (err.message || err), true); }
    };
    const rm = $("avatarRemove");
    if (rm) rm.onclick = () => saveAvatar(null);
    $("scrim").hidden = false;
    $("sheet").hidden = false;
  }

  /// The middle square of the picture, 160 pixels across, as a JPEG small
  /// enough to keep in the table.
  async function shrink(file) {
    const url = URL.createObjectURL(file);
    try {
      const img = await new Promise((resolve, reject) => { const i = new Image(); i.onload = () => resolve(i); i.onerror = () => reject(new Error("not a picture this browser can read")); i.src = url; });
      const side = Math.min(img.naturalWidth, img.naturalHeight), N = 160;
      const c = document.createElement("canvas");
      c.width = c.height = N;
      c.getContext("2d").drawImage(img, (img.naturalWidth - side) / 2, (img.naturalHeight - side) / 2, side, side, 0, 0, N, N);
      return c.toDataURL("image/jpeg", 0.82);
    } finally { URL.revokeObjectURL(url); }
  }

  async function saveAvatar(dataURL) {
    try {
      await api("crew_pairings?public_key=" + eq(state.me.publicKey), {
        method: "PATCH", headers: { Prefer: "return=minimal" }, body: JSON.stringify({ avatar: dataURL }),
      });
      state.members[state.me.publicKey] = { ...(state.members[state.me.publicKey] || { name: state.me.name }), avatar: goodAvatar(dataURL) };
      toast(dataURL ? "Picture saved." : "Picture removed.");
      closeSheet();
      render();
    } catch (e) {
      const missing = /avatar/i.test(e.message || "");
      toast(missing ? "Pictures aren't switched on yet: the owner needs to run the database update." : "Couldn't save it: " + (e.message || e), true);
    }
  }

  // MARK: Alerts

  const standalone = matchMedia("(display-mode: standalone)").matches || navigator.standalone;

  /// How he hears back: this browser while it's open, ntfy on his phone
  /// when it isn't, and a nudge to put the page on his home screen.
  function alertsBlock() {
    const topic = state.meRow?.alert_topic;
    const canNotify = "Notification" in window;
    const iOS = /iPhone|iPad/.test(navigator.userAgent);
    return section("Hearing back", "") + `
      <div class="alerts">
        ${canNotify && Notification.permission !== "granted" ? `<button class="chip" id="allowNotify">Notify me in this browser</button>` : ""}
        ${topic
          ? `<p>Answers are pushed to ntfy topic <b class="mono">${esc(topic)}</b>. Install the <a href="https://ntfy.sh/" target="_blank" rel="noopener">ntfy</a> app and subscribe to it, or <a href="https://ntfy.sh/${esc(topic)}" target="_blank" rel="noopener">open it on the web</a>.</p>
             <button class="chip" id="stopPush">Stop pushes</button>`
          : `<button class="chip" id="startPush">Push answers to my phone</button>`}
        ${!standalone ? `<p class="note">${iOS ? "Tip: Share → Add to Home Screen makes this an app." : "Tip: install this page as an app from the browser menu."}</p>` : ""}
      </div>`;
  }

  function wireAlerts() {
    const allow = $("allowNotify");
    if (allow) allow.onclick = async () => { await Notification.requestPermission(); render(); };
    const startPush = $("startPush");
    if (startPush) startPush.onclick = () => setTopic("portgas-" + [...crypto.getRandomValues(new Uint8Array(10))].map((b) => b.toString(16).padStart(2, "0")).join(""));
    const stopPush = $("stopPush");
    if (stopPush) stopPush.onclick = () => setTopic(null);
  }

  async function setTopic(topic) {
    try {
      await api("crew_pairings?public_key=" + eq(state.me.publicKey), {
        method: "PATCH", headers: { Prefer: "return=minimal" }, body: JSON.stringify({ alert_topic: topic }),
      });
      state.meRow = { ...(state.meRow || {}), alert_topic: topic };
      toast(topic ? "Subscribe to the topic in ntfy and you'll hear back there." : "Pushes off.");
      render();
    } catch (e) { toast("Couldn't save that: " + (e.message || e), true); }
  }

  function notify(title, body) {
    if (!("Notification" in window) || Notification.permission !== "granted") return;
    navigator.serviceWorker?.ready.then((r) => r.showNotification(title, { body, icon: "icon-192.png" }))
      .catch(() => { try { new Notification(title, { body }); } catch {} });
  }

  /// The desk, in plain words: what's switched on first, then the money in
  /// real and paper, each account, its open bets, and the autopilot.
  function renderDesk() {
    const d = state.desk;
    if (!d) {
      main.innerHTML = `<p class="empty">${state.deskLocked
        ? "The desk is sealed and the Mac hasn't handed this browser its key yet. It does within half a minute while portgas is open."
        : "The desk hasn't published yet."}</p>`;
      return;
    }
    const accounts = d.accounts || [], bets = d.bets || [];
    if (state.deskAccount && !accounts.some((a) => a.id === state.deskAccount)) state.deskAccount = null;
    const sum = (list, f) => list.reduce((a, x) => a + (f(x) || 0), 0);
    const real = accounts.filter((a) => a.isLive), paper = accounts.filter((a) => !a.isLive);
    const total = (list, label, cls) => list.length ? `
      <div class="total ${cls}">
        <span class="kicker">${label}</span>
        <b>${money(sum(list, (a) => a.equity))}</b>
        <span class="sm">${money(sum(list, (a) => a.cash))} cash · <span class="${tone(sum(list, (a) => a.unrealised))}">${signed(sum(list, (a) => a.unrealised))}</span> open</span>
      </div>` : "";
    const shown = state.deskAccount ? bets.filter((b) => betAccount(b, accounts)?.id === state.deskAccount) : bets;
    const groups = accounts.map((a) => [a, shown.filter((b) => betAccount(b, accounts)?.id === a.id)]).filter(([, list]) => list.length);
    const loose = shown.filter((b) => !betAccount(b, accounts));
    const dv = d.devil || {};
    main.innerHTML = `
      <div class="switches">
        ${switchRow(d.killSwitch ? "bad" : "ok", "Kill switch", d.killSwitch ? "ON: every bet is stopped" : "Off: betting is allowed")}
        ${switchRow(d.liveArmed ? "warn" : "", "Real money", d.liveArmed ? "Armed: real bets can be placed" : "Off: paper bets only")}
        ${switchRow(dv.isRunning ? "ok" : "", "Devil Mode", dv.isRunning ? `On, ${esc(cap(dv.aggression))}, betting on its own from ${esc(dv.accountName || "an account")}` : "Off: the Mac only bets when the owner approves")}
      </div>
      <div class="totals">${total(real, "Real money", "t-real")}${total(paper, "Paper (practice)", "t-paper")}</div>

      ${section("Accounts", accounts.length)}
      <p class="hint">Tap an account to see only its bets.</p>
      <div class="accounts">${accounts.map((a) => account(a, bets, d)).join("")}</div>

      ${section(shown.length ? `${shown.length} open bet${shown.length === 1 ? "" : "s"}${state.deskAccount ? " · " + esc(accounts.find((a) => a.id === state.deskAccount)?.name || "") : ""}` : "No open bets", shown.length ? signed(sum(shown, (b) => b.worth - b.stake)) : "")}
      ${state.deskAccount ? `<button class="chip clear" id="allBets">Show every account</button>` : ""}
      ${groups.map(([a, list]) => `
        <div class="group-head"><span>${esc(a.name)} ${a.isLive ? `<span class="real">REAL</span>` : `<span class="paper">PAPER</span>`}</span><span>${money(sum(list, (b) => b.stake))} in · <span class="${tone(sum(list, (b) => b.worth - b.stake))}">${signed(sum(list, (b) => b.worth - b.stake))}</span></span></div>
        ${list.map((b) => bet(b)).join("")}`).join("")}
      ${loose.map((b) => bet(b)).join("")}

      ${section("Devil Mode", dv.isRunning ? "ON" : "OFF")}
      <p class="hint">The Mac's autopilot. While it's on it places its own bets, inside the limits below.</p>
      <div class="kv"><span>Account</span><span>${esc(dv.accountName || "–")}</span></div>
      <div class="kv"><span>Style</span><span>${dv.isRunning ? esc(cap(dv.aggression)) : "Off"}</span></div>
      <div class="kv"><span>This session</span><span>${dv.sessionBets ?? 0} bets · <span class="${tone(dv.sessionResult)}">${signed(dv.sessionResult || 0)}</span></span></div>
      ${dv.maxStakePerBet ? `<div class="kv"><span>Most on one bet</span><span>${money(dv.maxStakePerBet)}</span></div>` : ""}
      ${dv.maxAtRisk ? `<div class="kv"><span>Most out at once</span><span>${money(dv.maxAtRisk)}</span></div>` : ""}
      ${dv.stopLoss ? `<div class="kv"><span>Stops after losing</span><span>${money(dv.stopLoss)}</span></div>` : ""}
      ${d.rank ? `<div class="kv"><span>Rank</span><span style="color:var(--gold)">${esc(d.rank)}</span></div>` : ""}
      <p class="foot">Published ${state.deskAt ? ago(state.deskAt) : "–"}${d.deviceName ? " from " + esc(d.deviceName) : ""}.</p>`;
    main.querySelectorAll("[data-account]").forEach((b) => b.onclick = () => {
      state.deskAccount = state.deskAccount === b.dataset.account ? null : b.dataset.account;
      renderDesk();
    });
    const all = $("allBets");
    if (all) all.onclick = () => { state.deskAccount = null; renderDesk(); };
    wireSells(main);
  }

  const switchRow = (cls, title, text) => `<div class="switch ${cls}"><i></i><b>${title}</b><span>${text}</span></div>`;

  /// The account a bet is in: by id, else by name for a desk from before ids.
  function betAccount(b, accounts) {
    return accounts.find((a) => b.accountID && a.id === b.accountID) || accounts.find((a) => b.accountName && a.name === b.accountName) || null;
  }

  function account(a, bets, d) {
    const mine = bets.filter((b) => betAccount(b, d.accounts) === a);
    const inBets = mine.reduce((s, b) => s + b.stake, 0);
    const last = a.sessions?.[0];
    return `
      <button class="account ${state.deskAccount === a.id ? "on" : ""}" data-account="${esc(a.id)}">
        <div class="nm"><span>${esc(a.name)}</span><span class="tags">${a.id === d.crewAccountID ? `<span class="crewdef">CREW PICKS</span>` : ""}${a.isLive ? `<span class="real">REAL</span>` : `<span class="paper">PAPER</span>`}</span></div>
        <div class="eq">${money(a.equity)}</div>
        <div class="arow"><span>Cash</span><span>${money(a.cash)}</span></div>
        <div class="arow"><span>In ${mine.length} bet${mine.length === 1 ? "" : "s"}</span><span>${money(inBets)}</span></div>
        <div class="arow"><span>Open profit</span><span class="${tone(a.unrealised)}">${signed(a.unrealised)}</span></div>
        ${last ? `<div class="arow"><span>Last session · ${esc(last.label)}</span><span class="${tone(last.result)}">${signed(last.result)}</span></div>` : ""}
        ${spark(a.curve)}
      </button>`;
  }

  /// An open bet: the pick and the match, what went in and at what price,
  /// what it's worth now, and a cash-out to suggest.
  function bet(b, linked = true) {
    const mv = b.worth - b.stake;
    return `
      <div class="bet">
        <div class="l1">
          <span class="bet-pick">${crest(b.homeCrest, "", b.homeName)}${crest(b.awayCrest, "", b.awayName)}<b>${esc(b.pick)}</b></span>
          <span class="mono ${tone(mv)}">${signed(mv)}</span>
        </div>
        <div class="l2"><span>${b.matchID && matchByID(b.matchID) ? `<a href="#m=${b.matchID}">${esc(b.homeName)} v ${esc(b.awayName)}</a>` : `${esc(b.homeName)} v ${esc(b.awayName)}`}</span><span class="${b.clockLive ? "down" : ""}">${esc(b.clock || "")}</span></div>
        <div class="bet-grid">
          <span><em>Put in</em>${money(b.stake)}</span>
          <span><em>Price</em>${cents(b.entry)} → ${cents(b.now)}</span>
          <span><em>Worth now</em>${money(b.worth)}</span>
        </div>
        <div class="l3">
          ${sellAsked(b.id) ? `<span class="up">Cash-out suggested</span>` : `<button class="sellbtn" data-sell="${esc(b.id)}">Suggest cash out · ${money(b.worth)}</button>`}
          ${linked ? polyLink(matchByID(b.matchID)?.slug) : ""}
        </div>
      </div>`;
  }

  function spark(values) {
    if (!values || values.length < 2) return "";
    const lo = Math.min(...values), hi = Math.max(...values), span = hi - lo || 1;
    const pts = values.map((v, i) => `${(i / (values.length - 1)) * 100},${30 - ((v - lo) / span) * 28}`).join(" ");
    const up = values[values.length - 1] >= values[0];
    return `<svg class="spark" viewBox="0 0 100 32" preserveAspectRatio="none"><polyline points="${pts}" fill="none" stroke="${up ? "#ff71eb" : "#b2381c"}" stroke-width="1.5" vector-effect="non-scaling-stroke"/></svg>`;
  }

  // MARK: Suggesting

  function openSheet(matchID, index, side = "yes") {
    const m = matchByID(matchID);
    if (!m) return;
    state.sheet = { matchID, index, side, stake: state.sheet?.stake || 10, note: "", accountID: startAccount() };
    drawSheet();
    $("scrim").hidden = false;
    $("sheet").hidden = false;
  }

  function closeSheet() {
    state.sheet = null;
    $("scrim").hidden = true;
    $("sheet").hidden = true;
  }

  function sellAsked(betID) {
    return state.picks.some((r) => r.status === "pending" && r.p?.kind === "sell" && r.p?.betID === betID);
  }

  function openSellSheet(betID) {
    const b = (state.desk?.bets || []).find((x) => x.id === betID);
    if (!b) return;
    state.sheet = { sell: betID, note: "" };
    const mv = b.worth - b.stake;
    $("sheet").innerHTML = `
      <div class="kicker">${esc(b.homeName)} v ${esc(b.awayName)}${b.clock ? " · " + esc(b.clock) : ""}</div>
      <h2>Cash out ${esc(b.pick)}</h2>
      <div class="sub">${money(b.stake)} in at ${cents(b.entry)} · now ${cents(b.now)}${b.isReal ? " · real money" : ""}</div>
      <div class="payout"><span>Worth now</span><b>${money(b.worth)} <span class="${tone(mv)}">(${signed(mv)})</span></b></div>
      <textarea id="note" rows="2" maxlength="140" placeholder="Why? (optional)" style="margin-top:12px"></textarea>
      <button class="go" id="send">Suggest cashing out</button>
      <button class="ghost" id="cancel">Cancel</button>`;
    $("cancel").onclick = closeSheet;
    $("send").onclick = () => suggestSell(b, $("note").value.trim());
    $("scrim").hidden = false;
    $("sheet").hidden = false;
  }

  async function suggestSell(b, note) {
    const btn = $("send");
    btn.disabled = true;
    btn.textContent = "Sending…";
    try {
      const id = crypto.randomUUID();
      const price = Math.min(0.99, Math.max(0.01, b.now ?? b.entry ?? 0.5));
      const payload = JSON.stringify({
        suggestionID: id, macID: state.me.macID, createdAt: Math.floor(Date.now() / 1000),
        matchID: b.matchID ?? 0, eventSlug: "", outcomeIndex: 0,
        stake: Math.max(0.01, Math.round(b.worth * 100) / 100), price,
        kind: "sell", betID: b.id, label: b.pick, ...(note ? { note } : {}),
      });
      await api("crew_suggestions", {
        method: "POST",
        headers: { Prefer: "return=minimal" },
        body: JSON.stringify({ id, device_id: state.me.macID, public_key: state.me.publicKey, payload, signature: await sign(payload), status: "pending" }),
      });
      state.picks.unshift({ id, status: "pending", payload, p: JSON.parse(payload), created_at: new Date().toISOString() });
      state.lastStatus[id] = "pending";
      ping(id);
      closeSheet();
      toast(`Sent. Cash out ${b.pick}, waiting for approval.`);
      buzz(20);
      render();
    } catch (e) {
      btn.disabled = false;
      btn.textContent = "Try again";
      toast("Couldn't send: " + (e.message || e), true);
    }
  }

  function drawSheet() {
    const s = state.sheet;
    const m = matchByID(s.matchID);
    if (!m) return closeSheet();
    const no = s.side === "no";
    const price = no ? m.noPrices?.[s.index] ?? null : m.prices[s.index];
    const label = [m.home, "Draw", m.away][s.index];
    // What a Yes and a No each mean, in words.
    const says = (n) => s.index === 1 ? (n ? "No draw" : "Draw") : n ? `${label} don't win` : `${label} to win`;
    // His limits, as the Mac last wrote them. The Mac checks its own copy.
    const capPick = Number(state.meRow?.max_stake) || Infinity;
    const capDay = Number(state.meRow?.daily_limit) || null;
    const presets = [5, 10, 20, 50, 100].filter((v) => v <= capPick);
    if (s.stake > capPick) s.stake = capPick;
    // Which account he'd like it in. The owner sees it and can still change it.
    const accounts = state.desk?.accounts || [];
    const acct = accounts.find((a) => a.id === s.accountID) || null;
    const left = leftToday(capDay);
    $("sheet").innerHTML = `
      <div class="kicker">${esc(m.home)} v ${esc(m.away)}${m.live ? ` · ${m.homeGoals ?? 0}–${m.awayGoals ?? 0} ${m.minute ?? ""}'` : " · " + esc(dayLabel(m.kickoff)) + " " + timeLabel(m.kickoff)}</div>
      <div class="yesno">
        <button data-side="yes" class="${no ? "" : "on"}"><b>Yes</b><span>${esc(says(false))}</span><em>${cents(m.prices[s.index])}</em></button>
        <button data-side="no" class="${no ? "on" : ""}" ${m.noPrices?.[s.index] == null ? "disabled" : ""}><b>No</b><span>${esc(says(true))}</span><em>${cents(m.noPrices?.[s.index])}</em></button>
      </div>
      <h2>${esc(says(no))}</h2>
      <div class="sub">${price == null ? "No price right now" : `${cents(price)} now · ${Math.round(price * 100)}% chance by the market`}</div>
      ${capPick < Infinity ? `<div class="sub">Your limit: ${money(capPick)} a pick${capDay ? ` · ${money(capDay)} a day, ${money(left)} left today` : ""}</div>` : ""}
      ${accounts.length ? `
        <div class="kicker acct-k">Into account</div>
        <div class="accts">${accounts.map((a) => `
          <button data-acct="${esc(a.id)}" class="${a.id === s.accountID ? "on" : ""} ${a.isLive ? "live" : ""}">
            <b>${esc(a.name)}</b><span>${a.isLive ? "REAL · " : ""}${money(a.cash)} cash</span>
          </button>`).join("")}</div>
        <div class="sub acct-note" id="acctNote">${acctNote(acct, s.stake)}</div>` : `<div class="sub acct-note">The owner picks the account.</div>`}
      <div class="stakes" style="grid-template-columns: repeat(${Math.max(1, presets.length)}, 1fr)">${presets.map((v) => `<button data-stake="${v}" class="${s.stake === v ? "on" : ""}">$${v}</button>`).join("")}</div>
      <div class="row"><span class="mono" style="color:var(--muted)">$</span><input id="stake" inputmode="decimal" value="${s.stake}" aria-label="Stake"></div>
      <div class="payout"><span>If it lands</span><b id="pays">${price ? money(s.stake / price) : "–"}</b></div>
      <textarea id="note" rows="2" maxlength="140" placeholder="Why? (optional)" style="margin-top:12px">${esc(s.note)}</textarea>
      <button class="go" id="send" ${price == null ? "disabled" : ""}>Suggest ${money(s.stake)}</button>
      <button class="ghost" id="cancel">Cancel</button>`;
    $("sheet").querySelectorAll("[data-stake]").forEach((b) => b.onclick = () => { s.stake = Number(b.dataset.stake); s.note = $("note").value; drawSheet(); });
    $("sheet").querySelectorAll("[data-side]").forEach((b) => b.onclick = () => { s.side = b.dataset.side; s.note = $("note").value; drawSheet(); });
    $("sheet").querySelectorAll("[data-acct]").forEach((b) => b.onclick = () => { s.accountID = b.dataset.acct; setPref("crew.account", s.accountID); s.note = $("note").value; drawSheet(); });
    $("stake").oninput = (e) => {
      s.stake = Math.max(0, Number(e.target.value.replace(",", ".")) || 0);
      $("pays").textContent = price ? money(s.stake / price) : "–";
      $("send").textContent = "Suggest " + money(s.stake);
      $("send").disabled = !(s.stake > 0) || s.stake > capPick || price == null;
      if (s.stake > capPick) $("send").textContent = "Over your " + money(capPick) + " limit";
      $("sheet").querySelectorAll("[data-stake]").forEach((b) => b.classList.toggle("on", Number(b.dataset.stake) === s.stake));
      if ($("acctNote")) $("acctNote").innerHTML = acctNote(acct, s.stake);
    };
    $("cancel").onclick = closeSheet;
    $("send").onclick = () => suggest(m, s.index, s.stake, $("note").value.trim(), price, s.side, acct);
  }

  /// The account a new pick starts in: the one he last chose, else the one
  /// the Mac puts crew picks in, else the first paper one.
  function startAccount() {
    const accounts = state.desk?.accounts || [];
    const ids = [pref("crew.account", null), state.desk?.crewAccountID];
    return ids.find((id) => id && accounts.some((a) => a.id === id)) || accounts.find((a) => !a.isLive)?.id || accounts[0]?.id || null;
  }

  function acctNote(a, stake) {
    if (!a) return "";
    if (a.isLive) return `<span class="warn">Real money.</span> The owner still has to approve it.`;
    if (stake > a.cash) return `<span class="warn">More than its ${money(a.cash)} cash.</span>`;
    return "Paper money: practice, nothing real.";
  }

  /// What's left of his day: the limit less today's placed picks.
  function leftToday(capDay) {
    if (!capDay) return Infinity;
    const today = new Date().toDateString();
    const used = state.picks.filter((r) => r.status === "placed" && r.p?.kind !== "sell" && new Date(r.created_at).toDateString() === today)
      .reduce((a, r) => a + (Number(r.p.stake) || 0), 0);
    return Math.max(0, capDay - used);
  }

  async function suggest(m, index, stake, note, price, side = "yes", account = null) {
    const btn = $("send");
    btn.disabled = true;
    btn.textContent = "Sending…";
    try {
      const id = crypto.randomUUID();
      const payload = JSON.stringify({
        suggestionID: id, macID: state.me.macID, createdAt: Math.floor(Date.now() / 1000),
        matchID: m.id, eventSlug: m.slug, outcomeIndex: index,
        stake: Math.round(stake * 100) / 100, price, ...(side === "no" ? { side: "no" } : {}), ...(note ? { note } : {}),
        // The account he'd like it in, and names for the crew's feed once
        // the match is off the board.
        ...(account ? { accountID: account.id, accountName: account.name } : {}),
        label: [m.home, "Draw", m.away][index], fixture: `${m.home} v ${m.away}`,
      });
      await api("crew_suggestions", {
        method: "POST",
        headers: { Prefer: "return=minimal" },
        body: JSON.stringify({ id, device_id: state.me.macID, public_key: state.me.publicKey, payload, signature: await sign(payload), status: "pending" }),
      });
      state.picks.unshift({ id, status: "pending", payload, p: JSON.parse(payload), created_at: new Date().toISOString() });
      state.lastStatus[id] = "pending";
      ping(id);
      closeSheet();
      toast(`Sent. ${money(stake)} on ${pickName(JSON.parse(payload))}${account ? " into " + account.name : ""}, waiting for approval.`);
      buzz(20);
      render();
    } catch (e) {
      btn.disabled = false;
      btn.textContent = "Try again";
      toast("Couldn't send: " + (e.message || e), true);
    }
  }

  // MARK: Little things

  function matchByID(id) { return (state.board?.matches || []).find((m) => m.id === id) || null; }
  /// The match's own page on Polymarket, opened in a new tab.
  function polyLink(slug, cls = "pm") {
    if (!slug) return "";
    return `<a class="${cls}" href="https://polymarket.com/event/${encodeURIComponent(slug)}" target="_blank" rel="noopener">Polymarket<span aria-hidden="true"> ↗</span></a>`;
  }
  function pickName(p) {
    if (!p) return "?";
    if (p.kind === "sell") return "Cash out " + (p.label || "a bet");
    const m = matchByID(p.matchID);
    const name = p.outcomeIndex === 1 ? "Draw" : m ? [m.home, "", m.away][p.outcomeIndex] : p.label || ["Home", "Draw", "Away"][p.outcomeIndex];
    return p.side === "no" ? "No on " + name : name;
  }
  /// "Home v Away" for a pick, from the board, else what the pick carried,
  /// else its market's name.
  function fixtureOf(p) {
    const m = matchByID(p?.matchID);
    if (m) return m.home + " v " + m.away;
    if (p?.fixture) return p.fixture;
    return p?.eventSlug ? p.eventSlug.replace(/-\d{4}-\d{2}-\d{2}$/, "").split("-").slice(1).join(" v ").toUpperCase() : "A match";
  }
  // Some feeds' crests are dead links; a broken-image icon reads as a bug, a
  // gap doesn't.
  function crest(url, cls = "", name = "") {
    const src = crestSrc(url);
    const blank = `<span class="crest blank ${cls}">${esc((name || "").trim().charAt(0))}</span>`;
    return src ? `<img class="crest ${cls}" src="${esc(src)}" alt="" loading="lazy" onerror="this.outerHTML='${blank.replace(/'/g, "&#39;").replace(/"/g, "&quot;")}'">` : blank;
  }

  /// The Mac bundles crests the feeds don't have, and names them by file;
  /// this site carries the same files. Polymarket's stand-in football for a
  /// club with no logo is no crest at all.
  function crestSrc(url) {
    if (!url) return null;
    const file = String(url).split("/").pop();
    if (String(url).startsWith("file:")) return /^crest-\d+\.png$/.test(file) ? "crests/" + file : null;
    if (decodeURIComponent(file).startsWith("soccer ball-")) return null;
    return url;
  }
  function cents(p) { return p == null ? "–" : Math.round(p * 100) + "¢"; }
  function money(v) { return "$" + (Math.abs(v) >= 1000 ? Math.round(v).toLocaleString() : (Math.round(v * 100) / 100).toFixed(2).replace(/\.00$/, "")); }
  function signed(v) { return (v > 0.005 ? "+" : v < -0.005 ? "−" : "") + money(Math.abs(v)); }
  function tone(v) { return v > 0.005 ? "up" : v < -0.005 ? "down" : ""; }
  function cap(s) { return s ? s[0].toUpperCase() + s.slice(1) : ""; }
  function esc(s) { return String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])); }
  function safeJSON(s) { try { return JSON.parse(s); } catch { return null; } }
  function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }
  function buzz(p) { try { navigator.vibrate?.(p); } catch {} }
  function timeLabel(iso) { return new Date(iso).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }); }
  /// The time today, else the day and the time: "Sat 17:30".
  function whenShort(iso) {
    const d = new Date(iso);
    return d.toDateString() === new Date().toDateString() ? timeLabel(iso) : d.toLocaleDateString([], { weekday: "short" }) + " " + timeLabel(iso);
  }
  /// How long until kickoff, short, for the timeline's rail.
  function untilShort(iso) {
    const s = (new Date(iso) - Date.now()) / 1000;
    if (s <= 0) return "now";
    if (s < 3600) return Math.round(s / 60) + "m";
    if (s < 86400) return Math.floor(s / 3600) + "h " + String(Math.floor((s % 3600) / 60)).padStart(2, "0") + "m";
    return Math.round(s / 86400) + "d";
  }
  function dayLabel(iso) {
    const d = new Date(iso), today = new Date();
    const t = new Date(today.getFullYear(), today.getMonth(), today.getDate());
    const diff = Math.round((new Date(d.getFullYear(), d.getMonth(), d.getDate()) - t) / 86400000);
    if (diff === 0) return "Today";
    if (diff === 1) return "Tomorrow";
    return d.toLocaleDateString([], { weekday: "long", day: "numeric", month: "long" });
  }
  function ago(date) {
    const s = Math.max(0, Math.round((Date.now() - date) / 1000));
    if (s < 60) return s + "s ago";
    if (s < 3600) return Math.round(s / 60) + " min ago";
    if (s < 86400) return Math.round(s / 3600) + " h ago";
    return Math.round(s / 86400) + " d ago";
  }

  let toastTimer;
  function toast(text, bad) {
    const t = $("toast");
    t.textContent = text;
    t.classList.toggle("bad", !!bad);
    t.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => (t.hidden = true), 4000);
  }

  // MARK: Start

  let timer;
  function start() {
    $("tabs").hidden = false;
    document.querySelectorAll("#tabs button").forEach((b) => b.onclick = () => {
      state.tab = b.dataset.tab;
      if (state.matchID) history.pushState(null, "", location.pathname);
      state.matchID = null;
      window.scrollTo(0, 0);
      render();
      if (state.tab === "crew") Promise.all([readMembers(), readFeed()]).then(render).catch(console.error);
    });
    route();
    let width = innerWidth;
    window.addEventListener("resize", () => { if (innerWidth !== width && state.matchID) { width = innerWidth; drawChart(matchByID(state.matchID) || {}); } });
    $("scrim").onclick = closeSheet;
    registerBox().catch(console.error);
    main.innerHTML = `<p class="empty">Loading the desk…</p>`;
    clearInterval(timer);
    refresh().catch(console.error);
    timer = setInterval(() => { if (!document.hidden) refresh().catch(console.error); }, 4000);
    document.addEventListener("visibilitychange", () => { if (!document.hidden) refresh().catch(console.error); });
  }

  /// #m=<id> opens a match page, so it has a link of its own: back works, and
  /// it opens in a new tab.
  function route() {
    const id = Number(new URLSearchParams(location.hash.slice(1)).get("m")) || null;
    if (id === state.matchID) return;
    state.matchID = id;
    if (id) state.tab = "matches";
    window.scrollTo(0, 0);
    if (state.me && state.board) render();
  }

  // A link pasted into the address bar of an open page changes only the part
  // after #, which reloads nothing.
  window.addEventListener("hashchange", () => { if (inviteFromLink()) location.reload(); else if (state.me) route(); });

  // Installable as an app, and how notifications are shown on phones.
  if ("serviceWorker" in navigator) navigator.serviceWorker.register("sw.js").catch(() => {});

  if (!KEY || !cfg.supabaseURL) {
    main.innerHTML = `<p class="empty">This page has no desk configured.</p>`;
  } else {
    const invite = inviteFromLink();
    if (invite && (!state.me || state.me.macID !== invite.mac)) renderJoin(invite);
    else if (state.me) start();
    else renderJoin(null);
  }
})();
