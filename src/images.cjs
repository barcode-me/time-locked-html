'use strict';
const fs = require('node:fs/promises');
const path = require('node:path');
const { tmpdir } = require('node:os');
const { fileURLToPath } = require('node:url');
const sharp = require('sharp');

const MAX_BYTES = 20 * 1024 * 1024;
const MAX_OUTPUT = 512 * 1024;
const MIME = { png: 'image/png', jpeg: 'image/jpeg', gif: 'image/gif', webp: 'image/webp' };

async function optimizeImage(data, expectedMime, { preserve = false } = {}) {
  if (!data.length || data.length > MAX_BYTES) throw Error('Image exceeds the 20 MiB input limit or is empty.');
  const options = { limitInputPixels: 32 * 1024 * 1024, animated: false };
  const info = await sharp(data, options).metadata();
  if (!MIME[info.format] || (expectedMime && MIME[info.format] !== expectedMime)) {
    throw Error('Image must contain matching PNG, JPEG, GIF or WebP bytes; SVG is not allowed.');
  }
  if (preserve) {
    const height = info.pageHeight || info.height;
    if (data.length > MAX_OUTPUT || info.width > 4096 || height > 4096 || info.width * height > 4 * 1024 * 1024) {
      throw Error('Preserved image exceeds the 512 KiB, 4096-pixel side or 4-megapixel limit.');
    }
    // Decode for validation only; embed the original bytes, including metadata and animation.
    await sharp(data, options).stats();
    return { mime: MIME[info.format], pixels: info.width * height, data };
  }
  // Rotate before resizing, strip metadata by default, and keep transparency.
  const pipeline = sharp(data, options).rotate().resize({ width: 1600, height: 1600, fit: 'inside', withoutEnlargement: true });
  for (const quality of [80, 65, 50]) {
    const { data: optimized, info: output } = await pipeline.clone().webp({ quality, effort: 4 }).toBuffer({ resolveWithObject: true });
    if (optimized.length <= MAX_OUTPUT) return { mime: 'image/webp', pixels: output.width * output.height, data: optimized };
  }
  throw Error('Optimized image exceeds the 512 KiB output limit.');
}

function imageSession(sourceDir) {
  let temporary;
  let downloaded = 0, totalBytes = 0;
  const cache = new Map();
  async function remote(url) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 10000);
    try {
      const response = await fetch(url, { signal: controller.signal, credentials: 'omit' });
      if (!response.ok) throw Error('Image download failed with HTTP ' + response.status + '.');
      if (Number(response.headers.get('content-length')) > MAX_BYTES) throw Error('Image exceeds the 20 MiB limit.');
      const chunks = []; let length = 0;
      if (!response.body) throw Error('Image response is empty.');
      for await (const chunk of response.body) {
        length += chunk.length;
        if (length > MAX_BYTES) { controller.abort(); throw Error('Image exceeds the 20 MiB limit.'); }
        totalBytes += chunk.length;
        if (totalBytes > 100 * 1024 * 1024) throw Error('Image downloads exceed the 100 MiB build limit.');
        chunks.push(chunk);
      }
      temporary ??= await fs.mkdtemp(path.join(tmpdir(), 'time-locked-images-'));
      const filename = path.join(temporary, String(downloaded++));
      await fs.writeFile(filename, Buffer.concat(chunks));
      return await fs.readFile(filename);
    } finally { controller.abort(); clearTimeout(timer); }
  }
  async function read(src) {
    if (cache.has(src)) return cache.get(src);
    if (cache.size >= 100) throw Error('Too many distinct images (maximum 100).');
    let data, expectedMime;
    if (/^data:/i.test(src)) {
      const match = /^data:(image\/(?:png|jpeg|gif|webp));base64,([A-Za-z0-9+/]+={0,2})$/i.exec(src);
      if (!match || match[2].length > Math.ceil(MAX_BYTES / 3) * 4) throw Error('Invalid or oversized Base64 raster image.');
      data = Buffer.from(match[2], 'base64');
      if (data.toString('base64') !== match[2]) throw Error('Invalid Base64 image encoding.');
      expectedMime = match[1].toLowerCase();
    } else if (/^https?:\/\//i.test(src)) data = await remote(src);
    else {
      if (/^[a-z][a-z\d+.-]*:/i.test(src) || src.startsWith('//')) throw Error('Unsupported image URL scheme.');
      const filename = fileURLToPath(new URL(src, require('node:url').pathToFileURL(path.join(sourceDir, '_page.html'))));
      const file = await fs.open(filename, 'r');
      try {
        const stat = await file.stat();
        if (!stat.isFile() || stat.size > MAX_BYTES) throw Error('Invalid or oversized local image.');
        data = await file.readFile();
      } finally { await file.close(); }
    }
    const entry = { data, expectedMime, results: new Map() };
    cache.set(src, entry);
    return entry;
  }
  async function load(src, { preserve = false } = {}) {
    const entry = await read(src);
    if (entry.results.has(preserve)) return entry.results.get(preserve);
    const info = await optimizeImage(entry.data, entry.expectedMime, { preserve });
    const result = { mime: info.mime, pixels: info.pixels, url: 'data:' + info.mime + ';base64,' + info.data.toString('base64') };
    entry.results.set(preserve, result);
    return result;
  }
  return { load, async close() { if (temporary) await fs.rm(temporary, { recursive: true, force: true }); } };
}
module.exports = { imageSession, optimizeImage };
