const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const { createDecipheriv, pbkdf2Sync } = require('node:crypto');
const { defaultChainInfo, defaultChainUrl, roundTime } = require('tlock-js');
const { encryptDrandPassword } = require('../src/crypto.cjs');
const { decryptPassword, roundForTimestamp } = require('../src/drand.cjs');
const { compileHTML, templateTree, buildFile } = require('../src/build.cjs');
const beacon = require('./fixtures/quicknet-round-1.json');
const genesis = defaultChainInfo.genesis_time * 1000;
const author = timestamp => `<template data-encrypted-block elementId="drand" password="KEY"><targets data-drand>{"timestamp":${JSON.stringify(timestamp)}}</targets><p>Private</p></template>`;

test('tlock wraps a password and recovers it using a verified published quicknet beacon', async t => {
  const clock = t.mock.method(Date, 'now', () => genesis - 1);
  const target = await encryptDrandPassword('secret 🔐', genesis);
  clock.mock.restore();
  t.mock.method(globalThis, 'fetch', async (url, options) => {
    assert.equal(url, defaultChainUrl + '/public/1');
    assert.equal(options.credentials, 'omit');
    return new Response(JSON.stringify(beacon));
  });
  assert.equal(await decryptPassword(target), 'secret 🔐');
  t.mock.method(globalThis, 'fetch', async () => new Response(JSON.stringify({ ...beacon, signature: '00'.repeat(48) })));
  await assert.rejects(decryptPassword(target));
});

test('drand rounds never precede timestamps, and future targets make no requests', async t => {
  for (const offset of [0, 1, 2999, 3000, 3001]) {
    const requested = genesis + offset;
    const actual = roundTime(defaultChainInfo, roundForTimestamp(requested));
    assert.ok(actual >= requested && actual - requested < 3000);
  }
  t.mock.method(globalThis, 'fetch', () => { throw Error('Unexpected request'); });
  const target = await encryptDrandPassword('secret', Date.now() + 60000);
  await assert.rejects(decryptPassword(target), /future/);
  await assert.rejects(encryptDrandPassword('secret', genesis), /future/);
  await assert.rejects(decryptPassword({ ...target, chainHash: 'wrong' }), /Invalid/);
});

test('compiles drand metadata, rejects untyped/mismatched targets, and bundles nested drand only when needed', async t => {
  const options = { passwords: { KEY: 'secret' } };
  const future = Date.now() + 86400000;
  const result = await compileHTML(author(future), options);
  const root = templateTree(result.html)[0];
  const block = JSON.parse(result.html.slice(root.end, root.contentEnd));
  assert.equal(block.type, undefined);
  assert.equal(block.targets[0].kind, 'drand');
  assert.equal(block.timestamp, undefined);
  assert.equal(block.targets[0].timestamp, future);
  assert.equal(block.targets[0].chainHash, defaultChainInfo.hash);
  assert.match(Buffer.from(block.targets[0].encryptedPassword, 'base64').toString(), /BEGIN AGE ENCRYPTED FILE/);
  assert.doesNotMatch(result.html, /secret|Private|data-drand/);
  const cipher = Buffer.from(block.data, 'base64');
  const decoder = createDecipheriv('aes-256-gcm', pbkdf2Sync('secret', Buffer.from(block.salt, 'base64'), 600000, 32, 'sha256'), Buffer.from(block.iv, 'base64'));
  decoder.setAuthTag(cipher.subarray(-16));
  assert.equal(Buffer.concat([decoder.update(cipher.subarray(0, -16)), decoder.final()]).toString(), '<p>Private</p>');
  for (const invalid of [author(future).replace('data-drand', ''), author(future).replace('data-drand', 'data-futured'), author('bad'), author(future).replace('<targets data-drand>', '<targets data-drand>[').replace('</targets>', ']</targets>'), author(future).replace('"timestamp":', '"other":')]) {
    await assert.rejects(compileHTML(invalid, options));
  }
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'drand-build-'));
  t.after(() => fs.rm(dir, { recursive: true, force: true }));
  const input = path.join(dir, 'page.html'), passwordFile = path.join(dir, 'passwords.env');
  await fs.writeFile(passwordFile, 'KEY=secret');
  const buildOptions = { buildDir: path.join(dir, 'build'), env: { PASSWORDS_FILE: passwordFile } };
  await fs.writeFile(input, '<template data-encrypted-block elementId="outer" password="KEY"><targets data-manual></targets>' + author(future) + '</template>');
  let output = await buildFile(input, buildOptions);
  let html = await fs.readFile(output.output, 'utf8');
  assert.ok(html.includes(defaultChainUrl));
  assert.doesNotMatch(html, /<script[^>]+src=/);
  await fs.writeFile(input, '<template data-encrypted-block elementId="outer" password="KEY"><targets data-manual></targets>Hi</template>');
  output = await buildFile(input, buildOptions);
  html = await fs.readFile(output.output, 'utf8');
  assert.ok(!html.includes(defaultChainUrl));
});
