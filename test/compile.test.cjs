const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const { createDecipheriv, pbkdf2Sync } = require('node:crypto');
const { compileHTML: compileHTMLRaw, buildFile, templateTree, resolveTargets } = require('../src/build.cjs');
const compileHTML = (html, options = {}) => compileHTMLRaw(html, { passwords: { p: 'p', outer: 'outer', inner: 'inner' }, ...options });
function decrypt(block, password) {
  const key = pbkdf2Sync(password, Buffer.from(block.salt, 'base64'), 600000, 32, 'sha256');
  const data = Buffer.from(block.data, 'base64');
  const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(block.iv, 'base64'));
  decipher.setAuthTag(data.subarray(-16));
  return Buffer.concat([decipher.update(data.subarray(0, -16)), decipher.final()]).toString('utf8');
}
function blocks(html) {
  return templateTree(html).filter(n => Object.hasOwn(n.attrs, 'data-encrypted-block'))
    .map(n => JSON.parse(html.slice(n.end, n.contentEnd)));
}
async function workspace(t) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'block-compiler-'));
  t.after(() => fs.rm(dir, { recursive: true, force: true }));
  return dir;
}

test('compiles nested HTML inside out with Unicode, fresh randomness and no authoring secrets', async () => {
  const source = '<h1>Public</h1><template data-encrypted-block elementId="outer" password="OUTER"><targets data-manual></targets>' +
    '<h2>Private 🔐</h2><template data-encrypted-block elementId="inner" password="INNER"><targets data-manual></targets>' +
    '<p>Inner &amp; content</p></template></template>';
  const options = { passwords: { OUTER: 'top-secret', INNER: 'a&b"c' } };
  const compiled = await compileHTML(source, options);
  assert.equal(compiled.count, 2);
  assert.ok(compiled.html.startsWith('<h1>Public</h1>'));
  assert.doesNotMatch(compiled.html, /top-secret|password-env|Private|Inner|a&amp;/);
  const outer = blocks(compiled.html)[0];
  const plain = decrypt(outer, 'top-secret');
  assert.match(plain, /Private 🔐/);
  assert.equal(decrypt(blocks(plain)[0], 'a&b"c'), '<p>Inner &amp; content</p>');
  assert.notEqual(blocks((await compileHTML(source, options)).html)[0].salt, outer.salt);
  assert.throws(() => decrypt(outer, 'wrong'));
});

test('preserves literal target JSON and derives the unlock date from body timestamps', async () => {
  const body = { namespace: '$namespace & literal', timestamp: 1798761600000 };
  const targets = [
    { url: 'https://example.com/hash', method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) },
    { url: 'https://example.com/unlock', body, responseType: 'json' }
  ];
  const source = `<template data-encrypted-block elementId="timed" password="KEY"><targets data-futured>${JSON.stringify(targets)}</targets><p>Timed</p></template>`;
  const result = await compileHTML(source, { passwords: { KEY: 'key' } });
  const block = blocks(result.html)[0];
  assert.equal(block.targets[0].timestamp, 1798761600000);
  assert.equal(block.targets[0].endpoints[0].body, targets[0].body);
  assert.deepEqual(JSON.parse(block.targets[0].endpoints[1].body), body);
  assert.equal(decrypt(block, 'key'), '<p>Timed</p>');
});

test('futured compilation uses password lookup without contacting targets', async t => {
  t.mock.method(globalThis, 'fetch', () => { throw Error('Compiler must not fetch passwords'); });
  const targets = [{ url: 'https://example.com/key', timestamp: '2099-01-01T00:00:00Z', namespace: 'test' }];
  const result = await compileHTML(`<template data-encrypted-block elementId="future" password="FUTURE"><targets data-futured>${JSON.stringify(targets)}</targets>Future</template>`, { passwords: { FUTURE: 'service-password' } });
  assert.equal(decrypt(blocks(result.html)[0], 'service-password'), 'Future');
  assert.doesNotMatch(result.html, /service-password/);
});

test('DNS targets compile as metadata and validate domain, key, and empty body', async () => {
  const source = '<template data-encrypted-block elementId="dns" password="p"><targets data-dns data-domain="Example.COM" data-txt-key="pass"></targets>Private</template>';
  const block = blocks((await compileHTML(source)).html)[0];
  assert.deepEqual(block.targets, [{ kind: 'dns', domain: 'example.com', txtKey: 'pass' }]);
  assert.equal(decrypt(block, 'p'), 'Private');
  for (const target of [
    '<targets data-dns data-domain="example.com"></targets>',
    '<targets data-dns data-domain="localhost" data-txt-key="pass"></targets>',
    '<targets data-dns data-domain="example.com" data-txt-key="bad key"></targets>',
    '<targets data-dns data-domain="example.com" data-txt-key="pass">text</targets>'
  ]) await assert.rejects(compileHTML('<template data-encrypted-block elementId="dns" password="p">' + target + 'Private</template>'));
});

test('tokenizer handles quoted >, comments, raw-text tags and ordinary template nesting', async () => {
  const prefix = '<!-- <template data-encrypted-block> -->\n<script>const x = "<template data-encrypted-block>";</script><textarea><template></textarea>';
  const result = await compileHTML(prefix + '<template data-encrypted-block elementId="x" password="p" title="a > b"><targets data-manual></targets><p>Keep</p><template><b>Inert</b></template></template>');
  assert.ok(result.html.startsWith(prefix));
  assert.equal(decrypt(blocks(result.html)[0], 'p'), '<p>Keep</p><template><b>Inert</b></template>');
});

test('malformed authoring, missing secrets fail closed', async () => {
  for (const source of [
    '<template data-encrypted-block elementId="x" password="p"><targets data-manual></targets>',
    '<template data-encrypted-block elementId="x" password="p"/>',
    '<template data-encrypted-block password="p"><targets data-manual></targets></template>',
    '<template data-encrypted-block elementId="x"><targets data-manual></targets></template>',
    '<template data-encrypted-block elementId="x" password="MISSING"><targets data-manual></targets></template>',
    '<template data-encrypted-block elementId="x" password="p"></template>',
    '<template><template data-encrypted-block elementId="x" password="p"><targets data-manual></targets></template></template>'
  ]) await assert.rejects(compileHTML(source, { passwords: {} }));
});

test('writes standalone build output, preserves source and does not overwrite a build after failure', async t => {
  const dir = await workspace(t);
  const input = path.join(dir, 'page.html');
  const buildDir = path.join(dir, 'build');
  const source = '<html><head></head><body><template data-encrypted-block elementId="x" password="KEY"><targets data-manual></targets>Secret</template></body></html>';
  await fs.writeFile(input, source);
  const passwordFile = path.join(dir, 'passwords.env');
  await fs.writeFile(passwordFile, 'KEY=password\n');
  const result = await buildFile(input, { buildDir, env: { PASSWORDS_FILE: passwordFile } });
  const compiled = await fs.readFile(result.output, 'utf8');
  assert.match(compiled, /<script>/);
  assert.doesNotMatch(compiled, /<script[^>]*src=/);
  assert.match(compiled, /<style data-pico-css>/);
  assert.match(compiled, /Pico CSS/);
  assert.equal((compiled.match(/<script/g) || []).length, 1);
  assert.equal(await fs.readFile(input, 'utf8'), source);
  assert.equal(decrypt(blocks(compiled)[0], 'password'), 'Secret');
  assert.deepEqual(await fs.readdir(buildDir), ['page.html']);
  await assert.rejects(buildFile(input, { buildDir, env: {} }));
  assert.equal(await fs.readFile(result.output, 'utf8'), compiled);
  await assert.rejects(buildFile(input, { buildDir: dir }), /overwrite/);
});

test('inline targets belong to their own nested block and are removed from plaintext', async () => {
  const target = url => '<targets data-futured>' + JSON.stringify([{ url, timestamp: 1000, namespace: 'test' }]) + '</targets>';
  const source = '<template data-encrypted-block elementId="outer" password="outer">' + target('https://example.com/outer') +
    '<p>Outer</p><template data-encrypted-block elementId="inner" password="inner">' + target('https://example.com/inner') + '<p>Inner</p></template></template>';
  const result = await compileHTML(source);
  const outer = blocks(result.html)[0];
  assert.equal(outer.targets[0].endpoints[0].url, 'https://example.com/outer');
  const plaintext = decrypt(outer, 'outer');
  assert.doesNotMatch(plaintext, /<targets data-futured>/);
  const inner = blocks(plaintext)[0];
  assert.equal(inner.targets[0].endpoints[0].url, 'https://example.com/inner');
  assert.equal(decrypt(inner, 'inner'), '<p>Inner</p>');
});

test('rejects missing or malformed target definitions', async () => {
  const good = '<targets data-futured>[{"url":"https://example.com/key"}]</targets>';
  for (const body of ['', '<targets data-futured>[]</targets>', '<targets data-futured>{}</targets>', '<targets data-futured>invalid</targets>', '<targets data-futured>', '<targets/>']) {
    await assert.rejects(compileHTML('<template data-encrypted-block elementId="x" password="p">' + body + '</template>'));
  }
  await assert.rejects(compileHTML('<template data-encrypted-block elementId="x" password="p"><targets data-manual>not empty</targets></template>'), /must be empty/);
});

test('targets timestamp validation rejects ambiguous dates ', async () => {
  const source = (targets, attrs = '') => `<template data-encrypted-block elementId="x" password="p" ${attrs}><targets data-futured>${JSON.stringify(targets.map(target => ({ namespace: 'test', ...target })))}</targets>Hi</template>`;
  for (const timestamp of [null, true, 'invalid']) {
    await assert.rejects(compileHTML(source([{ url: 'https://example.com', body: { timestamp } }])), /Invalid timestamp/);
  }
  await assert.rejects(compileHTML(source([{ url: 'https://example.com', timestamp: 1, body: { timestamp: 2 } }])), /same unlock timestamp/);
  await assert.rejects(compileHTML(source([{ url: 'https://example.com', timestamp: 1 }, { url: 'https://example.com', timestamp: 2 }])), /same unlock timestamp/);
  const block = blocks((await compileHTML(source([{ url: 'https://example.com', timestamp: '2027-01-01T00:00:00Z' }]))).html)[0];
  assert.equal(block.targets[0].timestamp, 1798761600000);
  await assert.rejects(compileHTML(source([{ url: 'https://example.com' }])), /requires a timestamp/);
});

test('password file supports quoted values and fails for missing, empty or whitespace passwords', async t => {
  const dir = await workspace(t);
  const passwordFile = path.join(dir, 'passwords.env');
  await fs.writeFile(passwordFile, '# private values\nKEY=" secret # value "\nEMPTY=\nSPACE="   "\n');
  const env = { PASSWORDS_FILE: passwordFile, MISSING: 'must-not-fall-back' };
  const source = name => `<template data-encrypted-block elementId="private" password="${name}"><targets data-manual></targets>Hello</template>`;
  const result = await compileHTMLRaw(source('KEY'), { env });
  assert.equal(decrypt(blocks(result.html)[0], ' secret # value '), 'Hello');
  assert.doesNotMatch(result.html, /secret # value|passwords.env|password="KEY"/);
  for (const name of ['EMPTY', 'SPACE', 'MISSING', 'toString', '']) await assert.rejects(compileHTMLRaw(source(name), { env }));
  await assert.rejects(compileHTMLRaw(source('KEY'), { env: {} }), /PASSWORDS_FILE/);
  await assert.rejects(compileHTMLRaw(source('KEY'), { env: { PASSWORDS_FILE: path.join(dir, 'missing.env') } }), /ENOENT/);
  await assert.rejects(compileHTMLRaw('<template data-encrypted-block elementId="private"><targets data-manual></targets>Hello</template>', { env }), /lookup name/);
});

test('multiple targets preserve author order and independent schedules with one AES password', async () => {
  const source = '<template data-encrypted-block elementId="choices" password="p">' +
    '<targets data-manual></targets>' +
    '<targets data-futured>[{"url":"https://example.com/one","timestamp":1000,"namespace":"one"}]</targets>' +
    '<targets data-drand>{"timestamp":"2099-01-01T00:00:00Z"}</targets>' +
    '<targets data-futured>[{"url":"https://example.com/two","timestamp":2000,"namespace":"two"}]</targets>Private</template>';
  const result = await compileHTML(source);
  const block = blocks(result.html)[0];
  assert.equal(block.type, undefined);
  assert.equal(block.timestamp, undefined);
  assert.deepEqual(block.targets.map(target => target.kind), ['manual', 'futured', 'drand', 'futured']);
  assert.equal(block.targets[1].timestamp, 1000);
  assert.equal(block.targets[3].timestamp, 2000);
  assert.ok(block.targets[2].encryptedPassword);
  assert.equal(result.usesDrand, true);
  assert.equal(decrypt(block, 'p'), 'Private');
  for (const target of ['<targets data-manual>password</targets>', '<targets data-manual data-futured></targets>', '<targets></targets>']) {
    await assert.rejects(compileHTML('<template data-encrypted-block elementId="bad" password="p">' + target + '</template>'));
  }
});

test('every futured endpoint requires a valid timestamp and nonempty namespace', async () => {
  const valid = { url: 'https://example.com/password', timestamp: 1000, namespace: 'example' };
  const source = targets => '<template data-encrypted-block elementId="x" password="p"><targets data-futured>' + JSON.stringify(targets) + '</targets>Secret</template>';
  for (const target of [
    { url: valid.url, namespace: 'example' },
    { url: valid.url, timestamp: 1000 },
    ...[null, '', '  ', 42, false].map(namespace => ({ ...valid, namespace })),
    ...[null, true, 'invalid'].map(timestamp => ({ ...valid, timestamp })),
    { url: valid.url, body: JSON.stringify({ timestamp: 1000 }) },
    { url: valid.url, body: JSON.stringify({ namespace: 'example' }) }
  ]) await assert.rejects(compileHTML(source([valid, target])), /timestamp|namespace/);
  for (const target of [valid, { url: valid.url, body: JSON.stringify({ namespace: 'example', timestamp: 1000 }) }]) {
    const block = blocks((await compileHTML(source([target]))).html)[0];
    assert.equal(block.targets[0].timestamp, 1000);
    assert.equal(decrypt(block, 'p'), 'Secret');
  }
});
