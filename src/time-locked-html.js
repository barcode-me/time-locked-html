/* Browser loader; drand dependencies are bundled only when needed. See README.md. */
(function () {
  "use strict";
  if (window.TimeLockedHTML) return;

  const records = new Map();
  const MAX_BLOCKS = 100;
  const MAX_DEPTH = 8;
  const MAX_HTML_LENGTH = 2 * 1024 * 1024;
  const SAFE_TAGS = new Set("p div span h1 h2 h3 h4 h5 h6 ul ol li dl dt dd strong em b i u s small sub sup blockquote pre code br hr table caption thead tbody tfoot tr th td".split(" "));
  const DRAND = null; // Included only for builds containing drand blocks.
  const FRAME_PICO = null; // Filled from the bundled asset during compilation.
  const FRAME_CSP = "default-src 'none'; script-src 'none'; style-src " + (FRAME_PICO ? "'" + FRAME_PICO.hash + "'" : "'none'") + "; style-src-attr 'none'; img-src data:; form-action 'none'; base-uri 'none'; object-src 'none'; frame-src 'none'";
  const POLL_MS = 1000;
  const RETRY_MS = 30000;
  const TIMEOUT_MS = 10000;
  if (window.TimeLockedHTMLDebug === undefined) window.TimeLockedHTMLDebug = true;
  let nextRadioGroup = 0;
  let debugPanel;
  let debugTitle;
  let debugList;
  let debugSnapshot = [];

  function updateDebug(queue) {
    if (window.TimeLockedHTMLDebug === false) {
      if (debugPanel) debugPanel.hidden = true;
      return;
    }
    if (!debugPanel) {
      debugPanel = document.createElement("details");
      debugPanel.open = true;
      debugPanel.setAttribute("aria-label", "Time-locked HTML debug panel");
      debugPanel.setAttribute("style", "position:fixed;bottom:12px;right:12px;z-index:2147483647;width:360px;max-width:calc(100vw - 48px);max-height:45vh;overflow:auto;padding:12px;border:1px solid #64748b;border-radius:8px;background:#0f172a;color:#f1f5f9;font:13px/1.5 system-ui,sans-serif;box-shadow:0 4px 16px #0004;text-align:left;");
      debugTitle = document.createElement("summary");
      debugTitle.setAttribute("style", "cursor:pointer;font-weight:600;");
      debugList = document.createElement("div");
      debugPanel.appendChild(debugTitle);
      debugPanel.appendChild(debugList);
      document.body.appendChild(debugPanel);
    }
    debugPanel.hidden = false;
    const entries = Array.isArray(queue) ? queue : [];
    debugTitle.textContent = "Blocks debug — " + entries.length + " loaded";
    if (entries.length === debugSnapshot.length && entries.every((raw, i) => raw === debugSnapshot[i])) return;
    debugSnapshot = entries.slice();
    debugList.innerHTML = "";
    entries.forEach((raw, index) => {
      const item = document.createElement("details");
      const title = document.createElement("summary");
      const json = document.createElement("pre");
      title.setAttribute("style", "cursor:pointer;margin-top:8px;");
      json.setAttribute("style", "white-space:pre-wrap;overflow-wrap:anywhere;font:12px/1.5 monospace;");
      title.textContent = "Block " + (index + 1);
      try {
        if (typeof raw !== "string") throw new Error("Not a JSON string");
        const parsed = JSON.parse(raw);
        if (parsed && typeof parsed.elementId === "string") title.textContent += " — " + parsed.elementId;
        json.textContent = JSON.stringify(parsed, null, 2);
      } catch (_) {
        title.textContent += " — invalid JSON entry";
        json.textContent = String(raw);
      }
      item.appendChild(title);
      item.appendChild(json);
      debugList.appendChild(item);
    });
  }

  function bytes(value) {
    if (typeof value !== "string") throw new Error("Expected base64 text.");
    return Uint8Array.from(atob(value), (c) => c.charCodeAt(0));
  }

  async function decrypt(password, block) {
    if (!window.crypto || !window.crypto.subtle) {
      throw new Error("Web Crypto requires HTTPS or localhost.");
    }
    const salt = bytes(block.salt);
    const iv = bytes(block.iv);
    const data = bytes(block.data);
    if (salt.length !== 16 || iv.length !== 12 || data.length < 16) {
      throw new Error("Invalid encrypted payload.");
    }
    const material = await window.crypto.subtle.importKey(
      "raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveKey"]
    );
    const key = await window.crypto.subtle.deriveKey(
      { name: "PBKDF2", salt, iterations: 600000, hash: "SHA-256" },
      material, { name: "AES-GCM", length: 256 }, false, ["decrypt"]
    );
    const result = await window.crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, data);
    return new TextDecoder("utf-8", { fatal: true }).decode(result);
  }

  function timestamp(value) {
    if (value == null) return 0;
    const ms = typeof value === "number" ? value : typeof value === "string" ?
      (/^-?\d+(?:\.\d+)?$/.test(value) ? Number(value) : Date.parse(value)) : NaN;
    if (!Number.isFinite(ms) || Number.isNaN(new Date(ms).getTime())) {
      throw new Error("timestamp must be Unix milliseconds or an ISO date string.");
    }
    return ms;
  }

  function futuredTimestamp(target) {
    const values = [target.timestamp];
    for (const endpoint of target.endpoints) {
      let body;
      try { body = JSON.parse(endpoint.body); } catch (_) { /* No JSON timestamp. */ }
      values.push(endpoint.timestamp, body?.timestamp);
    }
    const dates = values.filter(value => value !== undefined).map(value => {
      if (value === null) throw new Error("Invalid futured timestamp.");
      return timestamp(value);
    });
    if (dates.some(date => date !== dates[0])) throw new Error("Conflicting futured timestamps.");
    return dates[0] ?? 0;
  }

  function waitingForDate(record) {
    const choice = record.choices[record.active];
    if (choice.target.kind === "manual" || Date.now() >= choice.due) return false;
    record.status.textContent = "Content will be available on " + new Date(choice.due).toLocaleString() + ".";
    return true;
  }

  function element(id) {
    let node = document.getElementById(id);
    if (!node) {
      node = document.createElement("div");
      node.id = id;
      document.body.appendChild(node);
    }
    node.style.border = "1px solid #94a3b8";
    node.style.padding = "1rem";
    return node;
  }

  function register(raw, parent = null) {
    const depth = parent ? parent.depth + 1 : 0;
    if (depth > MAX_DEPTH) throw new Error("Nested block depth limit exceeded.");
    if (raw.length > MAX_HTML_LENGTH) throw new Error("Block is too large.");
    const block = JSON.parse(raw);
    if (!block || typeof block.elementId !== "string" || !block.elementId.trim()) {
      throw new Error("A nonempty elementId is required.");
    }
    const payload = block;
    if (bytes(payload.salt).length !== 16 || bytes(payload.iv).length !== 12 || bytes(payload.data).length < 16) {
      throw new Error("Invalid encrypted payload.");
    }
    if (!Array.isArray(block.targets) || !block.targets.length) throw new Error("Targets are required.");
    const choices = block.targets.map(target => {
      if (!target || typeof target !== "object" || Array.isArray(target)) throw new Error("Invalid target.");
      if (target.kind === "manual") return { target, due: 0 };
      if (target.kind === "dns") {
        if (typeof target.domain !== "string" || !/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(target.domain) ||
            typeof target.txtKey !== "string" || !/^[A-Za-z0-9_-]{1,64}$/.test(target.txtKey)) throw new Error("Invalid DNS target.");
        return { target, due: 0 };
      }
      if (target.kind === "futured") {
        if (!Array.isArray(target.endpoints) || !target.endpoints.length) throw new Error("HTTP endpoints required.");
        return { target, due: futuredTimestamp(target) };
      }
      if (target.kind === "drand") {
        if (!DRAND) throw new Error("This page was built without drand support.");
        return { target, due: DRAND.validateTarget(target) };
      }
      throw new Error("Unknown target kind.");
    });
    // Nested metadata cannot select or overwrite an element in the parent page.
    const host = parent ? document.createElement("div") : element(block.elementId);
    if (parent) {
      host.style.border = "1px solid #94a3b8";
      host.style.padding = "1rem";
      parent.host.appendChild(host);
    }
    const ui = document.createElement("div");
    const status = document.createElement("p");
    status.setAttribute("role", "status");
    ui.appendChild(status);
    host.appendChild(ui);
    const record = { block, payload, choices, active: 0, generation: 0, controller: new AbortController(), ui, status, host, depth, busy: false, done: false, next: 0 };
    targetControls(record);
    return record;
  }

  async function unlock(record, password, generation) {
    if (generation !== record.generation || record.done || waitingForDate(record)) return;
    const html = await decrypt(password, record.payload);
    if (generation !== record.generation || record.done || waitingForDate(record)) return;
    if (html.length > MAX_HTML_LENGTH) throw new Error("Decrypted HTML is too large.");
    const parsed = document.createElement("template");
    parsed.innerHTML = html; // Inert parsing only; never attach this fragment.
    const nested = Array.from(parsed.content.querySelectorAll("template[data-encrypted-block]"),
      (template) => template.content.textContent.trim()).slice(0, MAX_BLOCKS);
    const frame = document.createElement("iframe");
    frame.setAttribute("sandbox", "");
    frame.setAttribute("referrerpolicy", "no-referrer");
    frame.setAttribute("title", "Decrypted content: " + record.block.elementId);
    frame.setAttribute("style", "display:block;width:100%;height:320px;border:0;");
    frame.srcdoc = '<!doctype html><html><head><meta charset="utf-8">' +
      '<meta http-equiv="Content-Security-Policy" content="' + FRAME_CSP + '">' +
      (FRAME_PICO ? '<style>' + FRAME_PICO.css + '</style>' : '') + '</head><body>' +
      (await renderReadOnly(parsed.content)) + '</body></html>';
    if (generation !== record.generation || record.done || waitingForDate(record)) return;
    record.host.replaceChildren(frame);
    record.done = true;
    for (const raw of nested) discover(raw, record);
    scan();
  }

  function escapeText(text) {
    return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  }

  async function renderImage(node, budget) {
    if (++budget.count > 32) return "";
    const src = node.getAttribute("src") || "";
    const match = /^data:(image\/(?:png|jpeg|gif|webp));base64,([A-Za-z0-9+/]+={0,2})$/i.exec(src);
    if (!match || match[2].length > 699052) return "";
    try {
      const data = bytes(match[2]);
      if (!data.length || data.length > 524288) return "";
      const mime = match[1].toLowerCase();
      const signature = Array.from(data.slice(0, 12));
      const starts = expected => expected.every((byte, i) => signature[i] === byte);
      const valid = mime === "image/png" ? starts([137,80,78,71,13,10,26,10]) :
        mime === "image/jpeg" ? starts([255,216,255]) :
        mime === "image/gif" ? starts([71,73,70,56]) && [55,57].includes(data[4]) && data[5] === 97 :
        starts([82,73,70,70]) && data[8] === 87 && data[9] === 69 && data[10] === 66 && data[11] === 80;
      if (!valid) return "";
      const bitmap = await createImageBitmap(new Blob([data], { type: mime }));
      const width = bitmap.width, height = bitmap.height;
      bitmap.close();
      const pixels = width * height;
      if (!width || !height || width > 4096 || height > 4096 || pixels > 4194304 || budget.pixels + pixels > 8388608) return "";
      budget.pixels += pixels;
      let html = '<img src="' + src + '"';
      const alt = node.getAttribute("alt");
      if (alt !== null) html += ' alt="' + escapeText(alt).replace(/"/g, "&quot;") + '"';
      for (const name of ["width", "height"]) {
        const value = node.getAttribute(name) || "";
        if (/^[1-9]\d{0,3}$/.test(value) && Number(value) <= 4096) html += ' ' + name + '="' + value + '"';
      }
      return html + '>';
    } catch (_) { return ""; }
  }

  async function renderReadOnly(root, depth = 0, budget = { count: 0, pixels: 0 }) {
    if (depth > 100) return "";
    let result = "";
    for (const node of root.childNodes) {
      if (node.nodeType === 3) result += escapeText(node.textContent);
      else if (node.nodeType === 1 && node.namespaceURI === "http://www.w3.org/1999/xhtml") {
        const tag = node.localName;
        // Rebuild basic formatting only, with zero content-provided attributes.
        // Links become text; all other unsupported elements lose their subtree.
        if (tag === "img") result += await renderImage(node, budget);
        else if (tag === "a") result += await renderReadOnly(node, depth + 1, budget);
        else if (SAFE_TAGS.has(tag)) {
          result += "<" + tag + ">" + await renderReadOnly(node, depth + 1, budget);
          if (tag !== "br" && tag !== "hr") result += "</" + tag + ">";
        }
      }
    }
    return result;
  }

  function discover(raw, parent = null) {
    if (records.has(raw) || records.size >= MAX_BLOCKS) return;
    records.set(raw, null);
    try {
      records.set(raw, register(raw, parent));
    } catch (error) {
      console.error("TimeLockedHTML: skipped invalid block:", error.message);
    }
  }

  function targetControls(record) {
    const selector = document.createElement("fieldset");
    const legend = document.createElement("legend");
    legend.textContent = "Unlock using";
    selector.appendChild(legend);
    const group = "time-locked-target-" + (++nextRadioGroup);
    const names = { manual: "Enter password", futured: "Password service", drand: "Drand time lock", dns: "DNS TXT record" };
    record.choices.forEach((choice, index) => {
      const label = document.createElement("label");
      const radio = document.createElement("input");
      radio.type = "radio";
      radio.name = group;
      radio.value = String(index);
      radio.checked = index === 0;
      label.append(radio, document.createTextNode(names[choice.target.kind] + " (" + (index + 1) + ")"));
      selector.appendChild(label);
      radio.addEventListener("change", () => {
        if (!radio.checked || record.done || record.active === index) return;
        record.controller.abort();
        record.controller = new AbortController();
        record.generation++;
        record.active = index;
        record.busy = false;
        record.next = 0;
        showChoice(record);
        scan();
      });
    });
    record.ui.prepend(selector);
    record.manual = document.createElement("div");
    record.ui.appendChild(record.manual);
    showChoice(record);
  }

  function showChoice(record) {
    record.manual.replaceChildren();
    const choice = record.choices[record.active];
    if (choice.target.kind === "manual") passwordForm(record);
    else record.status.textContent = Date.now() < choice.due ?
      "Content will be available on " + new Date(choice.due).toLocaleString() + "." : "Waiting to check for an unlock password…";
  }

  function passwordForm(record) {
    const generation = record.generation;
    record.status.textContent = "Enter the password to unlock this content.";
    const form = document.createElement("form");
    const label = document.createElement("label");
    label.textContent = "Password ";
    const input = document.createElement("input");
    input.type = "password";
    input.autocomplete = "current-password";
    input.required = true;
    const button = document.createElement("button");
    button.type = "submit";
    button.textContent = "Decrypt";
    label.appendChild(input);
    form.append(label, button);
    record.manual.appendChild(form);
    form.addEventListener("submit", async event => {
      event.preventDefault();
      if (record.busy || record.done || generation !== record.generation) return;
      record.busy = true;
      button.disabled = true;
      record.status.textContent = "Decrypting…";
      try {
        await unlock(record, input.value, generation);
        input.value = "";
      } catch (_) {
        if (generation === record.generation) record.status.textContent = "Unable to decrypt. Check your password and try again.";
      } finally {
        if (generation === record.generation) record.busy = false;
        button.disabled = false;
      }
    });
  }

  async function fetchPassword(target, signal) {
    const url = new URL(target.url, document.baseURI);
    if (!/^https?:$/.test(url.protocol)) throw new Error("HTTP(S) targets required.");
    const controller = new AbortController();
    const abort = () => controller.abort();
    signal.addEventListener("abort", abort, { once: true });
    if (signal.aborted) controller.abort();
    const timer = setTimeout(abort, TIMEOUT_MS);
    try {
      const method = (target.method || "GET").toUpperCase();
      const response = await fetch(url.href, {
        method,
        headers: target.headers || {},
        body: method === "GET" || method === "HEAD" ? undefined : target.body,
        signal: controller.signal,
        cache: "no-store",
        credentials: "omit"
      });
      if (!response.ok) throw new Error("Password endpoint failed.");
      if (target.responseType === "json") {
        const json = await response.json();
        const password = typeof json === "string" ? json : json.password;
        if (typeof password !== "string") throw new Error("Expected a JSON password string.");
        return password;
      }
      return await response.text();
    } finally {
      clearTimeout(timer);
      signal.removeEventListener("abort", abort);
    }
  }

  async function fetchDnsPassword(target, resolver, signal) {
    const url = new URL(resolver);
    url.searchParams.set("name", target.domain);
    url.searchParams.set("type", "TXT");
    const controller = new AbortController();
    const abort = () => controller.abort();
    signal.addEventListener("abort", abort, { once: true });
    if (signal.aborted) controller.abort();
    const timer = setTimeout(abort, TIMEOUT_MS);
    try {
      const response = await fetch(url.href, { headers: { Accept: "application/dns-json" }, signal: controller.signal, cache: "no-store", credentials: "omit" });
      if (!response.ok) throw new Error("DNS resolver failed.");
      const result = await response.json();
      if (result.Status !== 0 || !Array.isArray(result.Answer)) throw new Error("No DNS TXT answer.");
      for (const answer of result.Answer) {
        if (answer.type !== 16 || typeof answer.data !== "string") continue;
        // DNS JSON encodes each TXT string as a quoted chunk. Join chunks in one record.
        const chunks = [...answer.data.matchAll(/"((?:\\.|[^"\\])*)"/g)];
        const txt = chunks.length ? chunks.map(match => match[1].replace(/\\(["\\])/g, "$1")).join("") : answer.data;
        const pairs = /(?:^|[;\s]+)([A-Za-z0-9_-]{1,64})\s*=\s*([\s\S]*?)(?=(?:[;\s]+[A-Za-z0-9_-]{1,64}\s*=)|$)/g;
        for (const match of txt.matchAll(pairs)) {
          if (match[1] !== target.txtKey) continue;
          const password = match[2].replace(/[;\s]+$/, "");
          if (password) return password;
        }
      }
      throw new Error("TXT key missing.");
    } finally {
      clearTimeout(timer);
      signal.removeEventListener("abort", abort);
    }
  }

  async function attempt(record) {
    const generation = record.generation;
    const signal = record.controller.signal;
    const choice = record.choices[record.active];
    record.busy = true;
    record.status.textContent = "Checking for an unlock password…";
    try {
      const endpoints = choice.target.kind === "futured" ? choice.target.endpoints : choice.target.kind === "dns" ?
        ["https://cloudflare-dns.com/dns-query", "https://dns.google/resolve"] : [choice.target];
      for (const endpoint of endpoints) {
        if (signal.aborted || generation !== record.generation || waitingForDate(record)) return;
        try {
          const password = choice.target.kind === "drand" ? await DRAND.decryptPassword(endpoint, signal) :
            choice.target.kind === "dns" ? await fetchDnsPassword(choice.target, endpoint, signal) : await fetchPassword(endpoint, signal);
          if (signal.aborted || generation !== record.generation) return;
          await unlock(record, password, generation);
          return;
        } catch (_) { /* Only HTTP endpoints within the active choice fall back. */ }
      }
      if (generation === record.generation) {
        record.status.textContent = "Content is still locked. Retrying in 30 seconds.";
        record.next = Date.now() + RETRY_MS;
      }
    } finally {
      if (generation === record.generation) record.busy = false;
    }
  }

  function scan() {
    if (!document.body) return;
    const templates = document.querySelectorAll("template[data-encrypted-block]");
    const queue = Array.from(templates, (template) => template.content.textContent.trim());
    for (const raw of queue) discover(raw);
    updateDebug(Array.from(records.keys()));
    for (const record of records.values()) {
      if (!record || record.done || record.busy) continue;
      const choice = record.choices[record.active];
      if (choice.target.kind === "manual") continue;
      if (Date.now() < choice.due) {
        record.status.textContent = "Content will be available on " + new Date(choice.due).toLocaleString() + ".";
      } else if (Date.now() >= record.next) {
        void attempt(record);
      }
    }
  }

  window.TimeLockedHTML = Object.freeze({ scan, decrypt });
  setInterval(scan, POLL_MS);
  scan();
})();
