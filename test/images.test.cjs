const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const sharp = require('sharp');
const { createDecipheriv, pbkdf2Sync } = require('node:crypto');
const { compileHTML, templateTree } = require('../src/build.cjs');
const { optimizeImage } = require('../src/images.cjs');
function plain(html) {
  const root = templateTree(html)[0], block = JSON.parse(html.slice(root.end, root.contentEnd));
  const data = Buffer.from(block.data, 'base64');
  const decoder = createDecipheriv('aes-256-gcm', pbkdf2Sync('secret', Buffer.from(block.salt, 'base64'), 600000, 32, 'sha256'), Buffer.from(block.iv, 'base64'));
  decoder.setAuthTag(data.subarray(-16));
  return Buffer.concat([decoder.update(data.subarray(0, -16)), decoder.final()]).toString();
}
const author = content => '<template data-encrypted-block elementId="x" password="KEY"><targets data-manual></targets>' + content + '</template>';
const options = { passwords: { KEY: 'secret' } };
const png = () => sharp({ create: { width: 16, height: 16, channels: 4, background: { r: 20, g: 100, b: 200, alpha: 0.5 } } }).png().toBuffer();

test('data-preserve embeds original bytes and caches each processing mode independently', async t => {
  const data = await sharp({ create: { width: 2400, height: 1200, channels: 3, background: '#227799' } }).jpeg().withMetadata({ orientation: 6 }).toBuffer();
  let downloads = 0;
  t.mock.method(globalThis, 'fetch', async () => { downloads++; return new Response(data); });
  for (const preservedFirst of [true, false]) {
    const preserved = '<img src="https://example.com/image.jpg" data-preserve="false" onerror="bad()">';
    const normal = '<img src="https://example.com/image.jpg">';
    const content = plain((await compileHTML(author(preservedFirst ? preserved + normal : normal + preserved), options)).html);
    const original = /data:image\/jpeg;base64,([^"]+)/.exec(content);
    assert.ok(original);
    assert.deepEqual(Buffer.from(original[1], 'base64'), data);
    assert.match(content, /data:image\/webp;base64,/);
    assert.doesNotMatch(content, /onerror/);
  }
  assert.equal(downloads, 2, 'one download per compilation, shared by both modes');
});

test('data-preserve works for local and Base64 images and rejects oversized originals', async t => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'preserved-image-'));
  t.after(() => fs.rm(dir, { recursive: true, force: true }));
  const data = await png();
  await fs.writeFile(path.join(dir, 'image.png'), data);
  const url = 'data:image/png;base64,' + data.toString('base64');
  const result = await compileHTML(author('<img data-preserve src="image.png">') + '<img data-preserve src="' + url + '">', { ...options, sourceDir: dir });
  assert.ok(plain(result.html).includes(url));
  assert.ok(result.html.includes('<img src="' + url + '">'));
  const wide = await sharp({ create: { width: 4100, height: 1, channels: 3, background: '#227799' } }).png().toBuffer();
  await assert.rejects(optimizeImage(wide, undefined, { preserve: true }), /Preserved image exceeds/);
  await assert.rejects(optimizeImage(Buffer.concat([data, Buffer.alloc(512 * 1024)]), undefined, { preserve: true }), /Preserved image exceeds/);
  await assert.rejects(optimizeImage(data, 'image/jpeg', { preserve: true }), /matching/);
});

test('resizes large images, strips metadata and produces lightweight WebP without upscaling', async () => {
  const data = await sharp({ create: { width: 2400, height: 1200, channels: 3, background: '#227799' } }).jpeg({ quality: 100 }).withMetadata().toBuffer();
  const result = await optimizeImage(data);
  const metadata = await sharp(result.data).metadata();
  assert.equal(metadata.width, 1600); assert.equal(metadata.height, 800);
  assert.equal(metadata.format, 'webp'); assert.equal(metadata.exif, undefined);
  assert.ok(result.data.length < data.length);
  const small = await sharp((await optimizeImage(await png())).data).metadata();
  assert.equal(small.width, 16); assert.equal(small.hasAlpha, true);
  await assert.rejects(optimizeImage(Buffer.from('<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1"/>')), /SVG/);
  await assert.rejects(optimizeImage(Buffer.alloc(20 * 1024 * 1024 + 1)), /20 MiB/);
});

test('downloads once to temporary storage, embeds inside encryption and cleans up', async t => {
  const image = await png(), directories = [], calls = [];
  const mkdtemp = fs.mkdtemp.bind(fs);
  t.mock.method(fs, 'mkdtemp', async prefix => { const dir = await mkdtemp(prefix); directories.push(dir); return dir; });
  t.mock.method(globalThis, 'fetch', async (url, opts) => { calls.push({ url, opts }); return new Response(image); });
  const result = await compileHTML(author('<img src="https://example.com/image.png" alt="a &quot;quote&quot;" onerror="bad()" srcset="https://example.com/other.png 2x">') + '<img src="https://example.com/image.png">', options);
  assert.equal(calls.length, 1); assert.equal(calls[0].opts.credentials, 'omit');
  assert.equal(directories.length, 1);
  await assert.rejects(fs.stat(directories[0]), { code: 'ENOENT' });
  const content = plain(result.html);
  assert.match(content, /src="data:image\/webp;base64,/);
  assert.doesNotMatch(content, /https:|onerror|srcset/);
  assert.match(result.html, /<img src="data:image\/webp;base64,/);
});

test('embeds relative files and data URLs; malformed images fail and temporary files are removed', async t => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'image-input-'));
  t.after(() => fs.rm(dir, { recursive: true, force: true }));
  const data = await png(); await fs.writeFile(path.join(dir, 'image.png'), data);
  const source = author('<img src="image.png"><img src="data:image/png;base64,' + data.toString('base64') + '">');
  const result = await compileHTML(source, { ...options, sourceDir: dir });
  assert.equal((plain(result.html).match(/data:image\/webp/g) || []).length, 2);
  const directories = [], mkdtemp = fs.mkdtemp.bind(fs);
  t.mock.method(fs, 'mkdtemp', async prefix => { const tmp = await mkdtemp(prefix); directories.push(tmp); return tmp; });
  t.mock.method(globalThis, 'fetch', async () => new Response('not an image'));
  await assert.rejects(compileHTML(author('<img src="https://example.com/bad">'), options));
  for (const tmp of directories) await assert.rejects(fs.stat(tmp), { code: 'ENOENT' });
  await assert.rejects(compileHTML(author('<img src="data:image/svg+xml;base64,PHN2Zz4=">'), options), /Invalid/);
  await assert.rejects(compileHTML(author('<img src="javascript:bad()">'), options), /scheme/);
});
