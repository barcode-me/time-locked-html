const { test } = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync, mkdtempSync, rmSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const { createServer } = require('node:http');
const { spawn } = require('node:child_process');
const { pbkdf2Sync, createCipheriv, randomBytes } = require('node:crypto');
const sharp = require('sharp');
const { encryptDrandPassword } = require('../src/crypto.cjs');
const { defaultChainInfo } = require('tlock-js');
const beacon = require('./fixtures/quicknet-round-1.json');
const { compileHTML, templateTree, inlineLoader } = require('../src/build.cjs');
const source = readFileSync(join(__dirname, '..', 'src', 'time-locked-html.js'), 'utf8');
function encrypt(html, password = 'correct') {
  const salt = randomBytes(16), iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', pbkdf2Sync(password, salt, 600000, 32, 'sha256'), iv);
  const data = Buffer.concat([cipher.update(html, 'utf8'), cipher.final(), cipher.getAuthTag()]);
  return { salt: salt.toString('base64'), iv: iv.toString('base64'), data: data.toString('base64') };
}
function block(id, html, extra = {}) {
  return { ...encrypt(html), elementId: id, targets: [{ kind: 'manual' }], ...extra };
}
const escapeJSON = value => JSON.stringify(value).replace(/</g, '\\u003c').replace(/>/g, '\\u003e').replace(/&/g, '\\u0026');
const hostile = `<h2 id="hijack" style="position:fixed" onclick="window.executed=1">Hello 🔐</h2>
<p>Read <a href="/unexpected" ping="/unexpected">this</a> &amp; enjoy.</p>
<script>parent.executed=1</script><script src="/unexpected"></script>
<img src="/unexpected" onerror="parent.executed=1"><style>@import '/unexpected';</style>
<link rel="stylesheet" href="/unexpected"><iframe src="/unexpected"></iframe>
<iframe srcdoc="<script>parent.executed=1</script>"></iframe>
<form action="/unexpected"><input><button>Send</button></form><button popovertarget="x">Open</button>
<svg onload="parent.executed=1"><a href="/unexpected">svg</a></svg><math><mtext>math</mtext></math>
<object data="/unexpected"></object><video src="/unexpected"></video>
<base href="https://invalid.example/"><meta http-equiv="refresh" content="0;url=/unexpected">
<evil-element>custom</evil-element>
<template data-encrypted-block elementId="victim" password="correct"><targets data-manual></targets><p>Nested content</p></template>`;
const fixtures = {
  hostile: block('main', hostile),
  future: block('future', 'Future', { targets: [{ kind: 'futured', timestamp: Date.now() + 3600000, endpoints: [{ url: '/unexpected' }] }] }),
  fallback: block('fallback', '<b>Unlocked</b>', { targets: [{ kind: 'futured', endpoints: [{ url: '/wrong' }, { url: '/password', method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{"token":"example"}', responseType: 'json' }, { url: '/unexpected' }] }] }),
  offline: block('offline', 'Offline', { targets: [{ kind: 'futured', endpoints: [{ url: '/offline' }] }, { kind: 'manual' }] }),
  scheduled: block('scheduled', '<p>Scheduled unlock</p>', { targets: [{ kind: 'futured', endpoints: [{ url: '/scheduled', method: 'POST', body: JSON.stringify({ timestamp: '2000000000000' }) }] }] }),
  text: block('text', '<i>Text</i>'),
  dns: block('dns', '<p>DNS unlocked</p>', { targets: [{ kind: 'dns', domain: 'example.com', txtKey: 'pass' }] }),
  dnsSpace: block('dns-space', 'Space DNS', { targets: [{ kind: 'dns', domain: 'space.example.com', txtKey: 'pass' }] })
};

async function browserChecks(fixtures) {
  const check = (condition, message) => { if (!condition) throw Error(message); };
  const until = async predicate => {
    for (let i = 0; i < 500; i++) { if (predicate()) return; await new Promise(r => setTimeout(r, 10)); }
    throw Error('Timed out waiting for browser state');
  };
  const add = value => {
    const template = document.createElement('template');
    template.content.appendChild(document.createTextNode(typeof value === 'string' ? value : JSON.stringify(value)));
    template.setAttribute('data-encrypted-block', '');
    document.body.appendChild(template);
    return template;
  };
  const submit = async (host, password) => {
    host.querySelector('input[type=password]').value = password;
    host.querySelector('form').dispatchEvent(new Event('submit', { cancelable: true }));
    await until(() => !host.querySelector('button')?.disabled);
  };
  const originalFetch = window.fetch.bind(window);
  let beaconRequests = 0;
  let heldResponse, heldSignal, heldRequests = 0;
  let scheduledRequests = 0, scheduledResponse;
  let cloudflareRequests = 0, googleRequests = 0;
  window.fetch = (url, options) => {
    if (String(url).startsWith('https://cloudflare-dns.com/dns-query?')) {
      cloudflareRequests++;
      const domain = new URL(url).searchParams.get('name');
      const data = domain === 'space.example.com' ? '"key1=value1 key2=value2 pass=correct"' : '"key1=value1; pass=wrong; key3=value3"';
      return Promise.resolve(new Response(JSON.stringify({ Status: 0, Answer: [{ type: 16, data }] }), { headers: { 'Content-Type': 'application/json' } }));
    }
    if (String(url).startsWith('https://dns.google/resolve?')) {
      googleRequests++;
      return Promise.resolve(new Response(JSON.stringify({ Status: 0, Answer: [{ type: 16, data: '"key1=value1; pass=cor" "rect; key3=value3"' }] }), { headers: { 'Content-Type': 'application/json' } }));
    }
    if (String(url).endsWith('/scheduled')) {
      scheduledRequests++;
      if (scheduledRequests === 1) return new Promise(resolve => { scheduledResponse = resolve; });
      return Promise.resolve(new Response('correct'));
    }
    if (String(url).endsWith('/held')) {
      heldRequests++;
      heldSignal = options.signal;
      return new Promise(resolve => { heldResponse = resolve; });
    }
    if (String(url).startsWith('https://api.drand.sh/')) {
      beaconRequests++;
      return originalFetch('/beacon', options);
    }
    return originalFetch(url, options);
  };
  add(fixtures.dns);
  TimeLockedHTML.scan();
  await until(() => document.querySelector('#dns iframe'));
  check(cloudflareRequests === 1 && googleRequests === 1, 'DNS resolver fallback failed');
  check(document.querySelector('#dns iframe').srcdoc.includes('DNS unlocked'), 'DNS password did not unlock');
  add(fixtures.dnsSpace);
  TimeLockedHTML.scan();
  await until(() => document.querySelector('#dns-space iframe'));
  check(cloudflareRequests === 2 && googleRequests === 1, 'DNS pair separators failed');
  add(fixtures.drandFuture);
  TimeLockedHTML.scan();
  await new Promise(resolve => setTimeout(resolve, 100));
  check(beaconRequests === 0, 'Future drand block fetched a beacon');
  check(document.getElementById('drand-future').textContent.includes('available on'), 'Drand date missing');
  add(fixtures.drand);
  TimeLockedHTML.scan();
  await until(() => document.querySelector('#drand iframe'));
  check(document.querySelector('#drand iframe').srcdoc.includes('Drand unlocked'), 'Drand password recovery failed');
  check(document.querySelector('#drand iframe').getAttribute('sandbox') === '', 'Drand sandbox missing');
  check(beaconRequests === 1, 'Unexpected beacon requests');
  const choose = (host, index) => {
    const radio = host.querySelectorAll('input[type=radio]')[index];
    radio.checked = true;
    radio.dispatchEvent(new Event('change', { bubbles: true }));
  };
  add(fixtures.choices);
  TimeLockedHTML.scan();
  const choices = document.getElementById('choices');
  check(choices.querySelector('input[type=radio]').checked && choices.querySelector('form'), 'First choice was not manual');
  check(heldRequests === 0 && beaconRequests === 1, 'Inactive choice made a request');
  choose(choices, 1);
  await until(() => heldRequests === 1);
  choose(choices, 0);
  check(heldSignal.aborted, 'Previous HTTP request was not aborted');
  heldResponse(new Response('correct'));
  await new Promise(resolve => setTimeout(resolve, 100));
  check(!choices.querySelector('iframe') && choices.querySelector('form'), 'Stale response unlocked after switching');
  check(choices.textContent.includes('Enter the password'), 'Stale request overwrote manual status');
  TimeLockedHTML.scan();
  check(heldRequests === 1 && beaconRequests === 1, 'Selection changed during polling');
  choose(choices, 2);
  await until(() => choices.querySelector('iframe'));
  check(beaconRequests === 2, 'Selected drand choice did not request beacon');
  check(choices.querySelector('iframe').srcdoc.includes('Multiple choices'), 'Selected drand choice did not unlock');
  const originalNow = Date.now;
  let now = 2000000000000 - 100;
  Date.now = () => now;
  add(fixtures.scheduled);
  TimeLockedHTML.scan();
  const scheduled = document.getElementById('scheduled');
  check(scheduled.textContent.includes(new Date(2000000000000).toLocaleString()), 'Endpoint body date was not displayed');
  check(scheduledRequests === 0 && !scheduled.querySelector('iframe'), 'Scheduled target started early');
  now = 2000000000000;
  TimeLockedHTML.scan();
  await until(() => scheduledRequests === 1);
  now -= 100;
  scheduledResponse(new Response('correct'));
  await new Promise(resolve => setTimeout(resolve, 100));
  check(!scheduled.querySelector('iframe'), 'Clock rollback allowed early decryption');
  now += 100;
  TimeLockedHTML.scan();
  await until(() => scheduled.querySelector('iframe'));
  check(scheduledRequests === 2, 'Scheduled target did not start at its timestamp');
  Date.now = originalNow;
  window.executed = 0;
  customElements.define('evil-element', class extends HTMLElement { connectedCallback() { window.executed++; } });
  add('{invalid'); add(fixtures.future); add(fixtures.hostile); add(fixtures.hostile);
  TimeLockedHTML.scan();
  const main = document.getElementById('main');
  await submit(main, 'wrong');
  check(main.textContent.includes('Check your password'), 'Wrong password retry missing');
  await submit(main, 'correct');
  const frame = main.querySelector('iframe');
  check(frame && frame.getAttribute('sandbox') === '', 'Sandbox missing');
  check(frame.getAttribute('referrerpolicy') === 'no-referrer', 'Referrer policy missing');
  check(frame.srcdoc.includes("default-src 'none'") && frame.srcdoc.includes("form-action 'none'"), 'CSP missing');
  const parsed = new DOMParser().parseFromString(frame.srcdoc, 'text/html');
  check(parsed.head.firstElementChild.tagName === 'META', 'Policy not placed in head');
  const pico = parsed.head.querySelector('style');
  check(pico?.textContent.includes('Pico CSS'), 'Bundled Pico CSS missing');
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(pico.textContent));
  const hash = 'sha256-' + btoa(String.fromCharCode(...new Uint8Array(digest)));
  check(parsed.head.querySelector('[http-equiv]').content.includes("style-src '" + hash + "'"), 'Pico hash mismatch');
  check(parsed.head.querySelector('[http-equiv]').content.includes("style-src-attr 'none'"), 'Style attributes not blocked');
  // A test-only readable frame lets us inspect computed CSS. Production frames
  // are separately checked for an empty sandbox and opaque origin below.
  const probe = document.createElement('iframe');
  probe.setAttribute('sandbox', 'allow-same-origin');
  const loaded = new Promise(resolve => probe.onload = resolve);
  probe.srcdoc = frame.srcdoc.replace('</head>', '<style>:root{--untrusted-css:yes}</style></head>')
    .replace('<body>', '<body style="--untrusted-attribute:yes">');
  document.body.appendChild(probe);
  await loaded;
  check(probe.contentWindow.getComputedStyle(probe.contentDocument.documentElement).getPropertyValue('--pico-font-family').trim(), 'Pico CSS was blocked');
  check(!probe.contentWindow.getComputedStyle(probe.contentDocument.documentElement).getPropertyValue('--untrusted-css').trim(), 'Other CSS was allowed');
  check(!probe.contentWindow.getComputedStyle(probe.contentDocument.body).getPropertyValue('--untrusted-attribute').trim(), 'Inline style attribute was allowed');
  probe.remove();
  check(parsed.body.innerHTML.includes('<h2>Hello 🔐</h2>'), 'Formatting or Unicode lost');
  check(!parsed.body.querySelector('script,img,style,link,iframe,form,input,button,svg,math,object,video,base,meta,template,evil-element,a'), 'Unsafe element retained');
  check([...parsed.body.querySelectorAll('*')].every(n => n.attributes.length === 0), 'Untrusted attributes retained');
  check(!document.querySelector('#hijack'), 'Decrypted markup reached parent DOM');
  check(document.getElementById('victim').textContent === 'Original', 'Nested destination overwrote existing content');
  const childHost = main.querySelector('div');
  check(childHost && childHost.querySelector('form'), 'Nested block not registered');
  check(main.querySelectorAll('form').length === 1, 'Nested duplicate registered');
  await submit(childHost, 'correct');
  check(childHost.querySelector('iframe').srcdoc.includes('<p>Nested content</p>'), 'Nested decryption failed');
  await until(() => frame.contentDocument === null);
  check(frame.contentWindow !== null, 'Frame did not load');
  check(window.executed === 0, 'Decrypted code ran');
  add(fixtures.image); TimeLockedHTML.scan();
  await submit(document.getElementById('image'), 'correct');
  const imageFrame = document.querySelector('#image iframe');
  const imageDoc = new DOMParser().parseFromString(imageFrame.srcdoc, 'text/html');
  const embeddedImage = imageDoc.body.querySelector('img');
  check(embeddedImage?.src.startsWith('data:image/webp;base64,'), 'Optimized image missing');
  check(!embeddedImage.hasAttribute('onerror') && !embeddedImage.hasAttribute('srcset'), 'Unsafe image attributes survived');
  const imageProbe = document.createElement('iframe'); imageProbe.setAttribute('sandbox', 'allow-same-origin');
  const imageLoaded = new Promise(resolve => imageProbe.onload = resolve);
  imageProbe.srcdoc = imageFrame.srcdoc; document.body.appendChild(imageProbe); await imageLoaded;
  check(imageProbe.contentDocument.querySelector('img').naturalWidth === 8, 'Embedded image did not load');
  imageProbe.remove();
  add(fixtures.fallback); add(fixtures.offline); add(fixtures.text);
  TimeLockedHTML.scan();
  await until(() => document.querySelector('#fallback iframe'));
  check(document.querySelector('#fallback iframe').srcdoc.includes('<b>Unlocked</b>'), 'Fallback failed');
  await until(() => document.getElementById('offline').textContent.includes('Retrying'));
  check(document.querySelector('#offline input[type=radio]').checked && !document.querySelector('#offline form'), 'Failed HTTP choice automatically selected manual');
  await submit(document.getElementById('text'), 'correct');
  check(document.querySelector('#text iframe').srcdoc.includes('<i>Text</i>'), 'Text decryption failed');
  TimeLockedHTML.scan();
  const corrected = add('{bad'); TimeLockedHTML.scan();
  corrected.content.textContent = JSON.stringify({ ...fixtures.hostile, elementId: 'corrected' });
  TimeLockedHTML.scan();
  check(document.querySelector('#corrected form'), 'Corrected template not discovered');
  window.TimeLockedHTMLDebug = false; TimeLockedHTML.scan();
  check(document.querySelector('[aria-label="Time-locked HTML debug panel"]').hidden, 'Debug disable failed');
  // Exercise browser-enforced CSP/sandbox even if a future filter regression
  // were to leave active markup behind. Keep the loader-generated policy.
  frame.srcdoc = frame.srcdoc.replace(/<body>[\s\S]*<\/body>/,
    '<body><script>parent.executed=1</script><script src="/unexpected"></script>' +
    '<img src="/unexpected"><link rel="stylesheet" href="/unexpected">' +
    '<style>@import "/unexpected";</style><iframe src="/unexpected"></iframe></body>');
  await new Promise(r => setTimeout(r, 300));
  check(window.executed === 0, 'Delayed decrypted code ran');
  return 'Sandbox, filtering, nested blocks, destination isolation, passwords, future dates, fallback, UTF-8 content, deduplication, template correction and debug switch passed';
}

test('real Chromium browser: secure rendering and loader regressions', { timeout: 30000 }, async t => {
  const genesis = defaultChainInfo.genesis_time * 1000;
  const clock = t.mock.method(Date, 'now', () => genesis - 1);
  const target = await encryptDrandPassword('correct', genesis);
  clock.mock.restore();
  fixtures.drand = block('drand', '<p>Drand unlocked</p>', { targets: [{ kind: 'drand', ...target }] });
  fixtures.choices = block('choices', '<p>Multiple choices</p>', { targets: [{ kind: 'manual' }, { kind: 'futured', endpoints: [{ url: '/held' }] }, { kind: 'drand', ...target }] });
  const future = await encryptDrandPassword('correct', Date.now() + 86400000);
  fixtures.drandFuture = block('drand-future', 'Future', { targets: [{ kind: 'drand', ...future }] });
  const loader = inlineLoader(source, undefined, { usesDrand: true }).tag;
  const child = await compileHTML('<template data-encrypted-block elementId="victim" password="correct"><targets data-manual></targets><p>Nested content</p></template>', { passwords: { correct: 'correct' } });
  fixtures.hostile = block('main', hostile.replace('<template data-encrypted-block elementId="victim" password="correct"><targets data-manual></targets><p>Nested content</p></template>', child.html));
  const png = await sharp({ create: { width: 8, height: 8, channels: 3, background: '#227799' } }).png().toBuffer();
  const built = await compileHTML('<template data-encrypted-block elementId="image" password="correct"><targets data-manual></targets><img src="data:image/png;base64,' + png.toString('base64') + '" alt="Example" onerror="parent.executed=1" srcset="/unexpected 2x"></template>', { passwords: { correct: 'correct' } });
  const root = templateTree(built.html)[0];
  fixtures.image = JSON.parse(built.html.slice(root.end, root.contentEnd));
  const calls = [];
  let resolveResult;
  const result = new Promise(resolve => { resolveResult = resolve; });
  const server = createServer(async (req, res) => {
    const chunks = []; for await (const chunk of req) chunks.push(chunk);
    const body = Buffer.concat(chunks).toString();
    if (req.url === '/') {
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.end('<!doctype html><div id="victim">Original</div>' + loader + '<script src="/checks.js"></script>');
    } else if (req.url === '/beacon') {
      res.setHeader('Content-Type', 'application/json'); res.end(JSON.stringify(beacon));
    } else if (req.url === '/loader.js') {
      res.setHeader('Content-Type', 'text/javascript; charset=utf-8'); res.end(source);
    } else if (req.url === '/checks.js') {
      res.setHeader('Content-Type', 'text/javascript; charset=utf-8');
      res.end(`(${browserChecks.toString()})(${escapeJSON(fixtures)}).then(value => fetch('/result', {method:'POST',body:JSON.stringify({value})})).catch(error => fetch('/result', {method:'POST',body:JSON.stringify({error:error.stack})}));`);
    } else if (req.url === '/result') { resolveResult(JSON.parse(body)); res.end('ok'); }
    else {
      calls.push({ url: req.url, method: req.method, body });
      if (req.url === '/wrong') res.end('wrong');
      else if (req.url === '/password') { res.setHeader('Content-Type', 'application/json'); res.end('{"password":"correct"}'); }
      else { res.statusCode = 404; res.end('unavailable'); }
    }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const profile = mkdtempSync(join(tmpdir(), 'time-locked-browser-'));
  const chrome = process.env.CHROME_BIN || '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
  const browser = spawn(chrome, ['--headless=new', '--disable-gpu', '--no-first-run', '--no-default-browser-check', '--disable-background-networking', '--user-data-dir=' + profile, `http://127.0.0.1:${server.address().port}/`], { stdio: 'ignore' });
  let timer;
  try {
    const outcome = await Promise.race([result, new Promise((_, reject) => {
      timer = setTimeout(() => reject(Error('Browser test timed out')), 20000);
      browser.once('error', reject);
      browser.once('exit', code => reject(Error('Browser exited early: ' + code)));
    })]);
    assert.equal(outcome.error, undefined, outcome.error);
    assert.equal(calls.filter(c => c.url === '/unexpected').length, 0, 'Blocked resource was fetched');
    assert.equal(calls.filter(c => c.url === '/offline').length, 1, 'Failed round retried too soon');
    assert.deepEqual(calls.filter(c => c.url === '/password'), [{ url: '/password', method: 'POST', body: '{"token":"example"}' }]);
    console.log(outcome.value);
  } finally {
    clearTimeout(timer);
    browser.kill();
    await new Promise(resolve => { if (browser.exitCode !== null) resolve(); else browser.once('exit', resolve); });
    await new Promise(resolve => server.close(resolve));
    rmSync(profile, { recursive: true, force: true });
  }
});
