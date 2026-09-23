const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const vm = require('node:vm');
const { createHash } = require('node:crypto');
const { buildFile, inlineLoader } = require('../src/build.cjs');
const minifyLoader = source => inlineLoader(source).tag.slice('<script>'.length, -'</script>'.length);

test('build embeds one minified loader and writes no external loader in a fresh build directory', async t => {
  const dir = await fs.mkdtemp(join(tmpdir(), 'inline-build-'));
  t.after(() => fs.rm(dir, { force: true, recursive: true }));
  const input = join(dir, 'page.html'), buildDir = join(dir, 'build');
  const original = '<html><head></head><body>' +
    '<template data-encrypted-block elementId="secret" password="KEY"><targets data-manual></targets><p>Private text</p></template>' +
    '</body></html>';
  await fs.writeFile(input, original);
  const passwordFile = join(dir, 'passwords.env');
  await fs.writeFile(passwordFile, 'KEY=build-secret\n');
  const result = await buildFile(input, { buildDir, env: { PASSWORDS_FILE: passwordFile } });
  const html = await fs.readFile(result.output, 'utf8');
  assert.equal(result.count, 1);
  assert.match(html, /<style data-pico-css>/);
  assert.match(html, /Pico CSS/);
  assert.equal((html.match(/<script>/g) || []).length, 1);
  assert.doesNotMatch(html, /<script[^>]*src=|Private text|build-secret|password-env/);
  assert.match(html, /<template data-encrypted-block>/);
  assert.ok(result.minifiedBytes < result.originalBytes);
  assert.deepEqual(await fs.readdir(buildDir), ['page.html']);
  assert.equal(await fs.readFile(input, 'utf8'), original);
  await assert.rejects(buildFile(input, { buildDir, env: {} }));
  assert.equal(await fs.readFile(result.output, 'utf8'), html);
});

test('minification preserves strings, regexes, token separation and ASI', () => {
  const source = `/* header */
    const url = "https://example.com/a//b";
    const regex = /[a/b]+/g;
    function f() { return\n      123; }
    const value = 10 / 2;
    const separated = 1 + +2; // preserve token boundary
    globalThis.result = [url, 'escaped\\"quote', '/*literal*/', regex.source, f(), value, separated];
  `;
  const original = {}, compressed = {};
  vm.runInNewContext(source, original);
  vm.runInNewContext(minifyLoader(source), compressed);
  assert.equal(JSON.stringify(compressed.result), JSON.stringify(original.result));
  assert.ok(minifyLoader(source).length < source.length);
  const modern = {};
  vm.runInNewContext(minifyLoader('globalThis.value = `hello ${1 + 2}`;'), modern);
  assert.equal(modern.value, 'hello 3');
  assert.throws(() => minifyLoader('const = broken;'));
});

test('inline script escaping preserves string values and CSP hash matches exact script bytes', () => {
  const result = inlineLoader('globalThis.value = "</ScRiPt><p>text</p>";');
  const code = result.tag.slice('<script>'.length, -'</script>'.length);
  assert.doesNotMatch(code, /<\/script/i);
  const context = {}; vm.runInNewContext(code, context);
  assert.equal(context.value, '</ScRiPt><p>text</p>');
  assert.equal(result.cspHash, 'sha256-' + createHash('sha256').update(code).digest('base64'));
});
