#!/usr/bin/env node
'use strict';

const fs = require('node:fs/promises');
const { readFileSync } = require('node:fs');
const path = require('node:path');
const { randomBytes, createHash } = require('node:crypto');
const { encrypt, encryptDrandPassword } = require('./crypto.cjs');
const { minify_sync } = require('terser');
const { parse: parseEnv } = require('dotenv');
const { imageSession } = require('./images.cjs');
const MAX_SIZE = 2 * 1024 * 1024;
const MAX_BLOCKS = 100;
const MAX_DEPTH = 8;
const PAGE_LAYOUT_CSS = '\nbody { padding: 1rem; }\n';

// Authoring tokenizer: preserves source bytes, understands quoted attributes,
// comments and raw-text elements, and requires explicitly balanced templates.
// This is not an HTML sanitizer; display security belongs to the browser loader.
function decodeAttribute(value) {
  return value.replace(/&(#x[\da-f]+|#\d+|[a-z][\da-z]*);/gi, (_, entity) => {
    const named = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: '\u00a0' };
    if (entity[0] !== '#') {
      if (!(entity in named)) throw Error(`Unsupported attribute entity &${entity}; use a numeric entity.`);
      return named[entity];
    }
    const cp = /^#x/i.test(entity) ? parseInt(entity.slice(2), 16) : Number(entity.slice(1));
    if (!cp || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) throw Error('Invalid numeric attribute entity.');
    return String.fromCodePoint(cp);
  });
}

function tokenize(html) {
  const tokens = [];
  const rawTags = new Set(['script', 'style', 'textarea', 'title', 'xmp', 'iframe', 'noembed', 'noframes']);
  let i = 0;
  while (i < html.length) {
    const start = html.indexOf('<', i);
    if (start < 0) break;
    if (html.startsWith('<!--', start)) {
      const end = html.indexOf('-->', start + 4);
      if (end < 0) throw Error('Unclosed HTML comment.');
      i = end + 3; continue;
    }
    const match = /^<(\/?)\s*([a-z][\w:-]*)(?=[\s/>])/i.exec(html.slice(start));
    if (!match) { i = start + 1; continue; }
    const name = match[2].toLowerCase();
    const closing = !!match[1];
    let pos = start + match[0].length;
    const attrs = Object.create(null);
    let selfClosing = false;
    while (pos < html.length) {
      while (/\s/.test(html[pos] || '') && pos < html.length) pos++;
      if (html[pos] === '>') { pos++; break; }
      if (html.startsWith('/>', pos)) { selfClosing = true; pos += 2; break; }
      const attr = /^[^\s=<>/"']+/.exec(html.slice(pos));
      if (!attr || closing) throw Error(`Invalid <${name}> attributes near offset ${pos}.`);
      const key = attr[0].toLowerCase(); pos += attr[0].length;
      while (/\s/.test(html[pos] || '') && pos < html.length) pos++;
      let value = '';
      if (html[pos] === '=') {
        pos++;
        while (/\s/.test(html[pos] || '') && pos < html.length) pos++;
        const quote = html[pos];
        if (quote === '"' || quote === "'") {
          const end = html.indexOf(quote, ++pos);
          if (end < 0) throw Error(`Unclosed ${key} attribute.`);
          value = html.slice(pos, end); pos = end + 1;
        } else {
          const unquoted = /^[^\s>]+/.exec(html.slice(pos));
          if (!unquoted) throw Error(`Missing ${key} attribute value.`);
          value = unquoted[0]; pos += value.length;
        }
      }
      if (Object.hasOwn(attrs, key)) throw Error(`Duplicate ${key} attribute.`);
      attrs[key] = decodeAttribute(value);
    }
    if (html[pos - 1] !== '>') throw Error(`Unclosed <${name}> tag.`);
    const token = { name, closing, attrs, start, end: pos, selfClosing };
    tokens.push(token);
    i = pos;
    if (!closing && name === 'plaintext') throw Error('<plaintext> is not supported in authoring HTML.');
    if (!closing && rawTags.has(name)) {
      const endPattern = new RegExp('</' + name + '\\s*>', 'ig');
      endPattern.lastIndex = pos;
      const end = endPattern.exec(html);
      if (!end) throw Error(`Unclosed <${name}> element.`);
      tokens.push({ name, closing: true, attrs: {}, start: end.index, end: endPattern.lastIndex });
      i = endPattern.lastIndex;
    }
  }
  return tokens;
}

function templateTree(html) {
  const roots = [], stack = [];
  for (const token of tokenize(html)) {
    if (token.name !== 'template') continue;
    if (token.selfClosing) throw Error('Templates must have an explicit </template>.');
    if (!token.closing) {
      const node = { ...token, children: [] };
      (stack.length ? stack[stack.length - 1].children : roots).push(node);
      stack.push(node);
    } else {
      const node = stack.pop();
      if (!node) throw Error('Unexpected </template>.');
      node.contentEnd = token.start; node.closeEnd = token.end;
    }
  }
  if (stack.length) throw Error('Unclosed <template>.');
  return roots;
}

function resolveTargets(template) {
  if (!Array.isArray(template) || !template.length) throw Error('<targets> must contain a nonempty JSON array.');
  return template.map(item => {
    if (!item || typeof item !== 'object' || Array.isArray(item)) throw Error('Invalid target object.');
    const target = { ...item };
    if (target.body !== undefined && typeof target.body !== 'string') target.body = JSON.stringify(target.body);
    const contentType = Object.entries(target.headers || {}).find(([key]) => key.toLowerCase() === 'content-type')?.[1] || '';
    if (target.body !== undefined && /(?:application\/json|\+json)(?:;|$)/i.test(contentType)) JSON.parse(target.body);
    let body;
    try { body = JSON.parse(target.body); } catch { /* Metadata may be on the endpoint itself. */ }
    if (target.timestamp === undefined && body?.timestamp === undefined) {
      throw Error('Each futured endpoint requires a timestamp.');
    }
    targetsTimestamp([target]);
    const namespaces = [target.namespace, body?.namespace].filter(value => value !== undefined);
    if (!namespaces.length || namespaces.some(value => typeof value !== 'string' || !value.trim())) {
      throw Error('Each futured endpoint requires a nonempty namespace.');
    }
    if (typeof target.url !== 'string' || !/^https?:$/.test(new URL(target.url).protocol)) throw Error('Target requires an absolute HTTP(S) URL.');
    target.method = (target.method || 'GET').toUpperCase();
    if (target.responseType && !['json', 'text'].includes(target.responseType)) throw Error('responseType must be json or text.');
    return target;
  });
}

function targetsTimestamp(targets) {
  const timestamps = [];
  for (const target of targets || []) {
    let body;
    try { body = JSON.parse(target.body); } catch { /* Non-JSON bodies have no implicit timestamp. */ }
    for (const value of [target.timestamp, body?.timestamp]) {
      if (value === undefined) continue;
      const timestamp = typeof value === 'number' ? value :
        typeof value === 'string' ? (/^-?\d+(?:\.\d+)?$/.test(value) ? Number(value) : Date.parse(value)) : NaN;
      if (!Number.isFinite(timestamp) || Number.isNaN(new Date(timestamp).getTime())) throw Error('Invalid timestamp in targets JSON.');
      timestamps.push(timestamp);
    }
  }
  if (timestamps.some(value => value !== timestamps[0])) throw Error('Targets must use the same unlock timestamp within one futured target.');
  return timestamps[0];
}

function extractTargets(content) {
  let depth = 0, opening = null;
  const sections = [];
  for (const token of tokenize(content)) {
    if (token.name === 'template') depth += token.closing ? -1 : 1;
    if (depth || token.name !== 'targets') continue;
    if (!token.closing) {
      const attrs = Object.keys(token.attrs);
      if (opening || token.selfClosing ||
          !((attrs.length === 1 && ['data-manual', 'data-futured', 'data-drand'].includes(attrs[0])) ||
            (attrs.length === 3 && attrs.includes('data-dns') && attrs.includes('data-domain') && attrs.includes('data-txt-key')))) throw Error('Invalid <targets> element.');
      opening = { ...token, kind: Object.hasOwn(token.attrs, 'data-dns') ? 'dns' : attrs[0].slice(5) };
    } else {
      if (!opening) throw Error('Unexpected </targets>.');
      sections.push({ start: opening.start, end: token.end, kind: opening.kind, attrs: opening.attrs, json: content.slice(opening.end, token.start) });
      opening = null;
    }
  }
  if (opening) throw Error('Unclosed <targets>.');
  if (!sections.length) throw Error('Each block requires at least one <targets> element.');
  const targets = sections.map(section => {
    if (section.kind === 'manual') {
      if (section.json.trim()) throw Error('Manual targets must be empty.');
      return { kind: 'manual' };
    }
    if (section.kind === 'dns') {
      if (section.json.trim()) throw Error('DNS targets must be empty.');
      const domain = section.attrs['data-domain'];
      const txtKey = section.attrs['data-txt-key'];
      if (typeof domain !== 'string' || domain.length > 253 || !/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?\.?$/i.test(domain)) throw Error('DNS target requires a valid domain.');
      if (typeof txtKey !== 'string' || !/^[A-Za-z0-9_-]{1,64}$/.test(txtKey)) throw Error('DNS target requires a valid TXT key.');
      return { kind: 'dns', domain: domain.toLowerCase().replace(/\.$/, ''), txtKey };
    }
    const value = JSON.parse(section.json);
    if (section.kind === 'drand') return { kind: 'drand', ...drandTargets(value) };
    const endpoints = resolveTargets(value);
    const timestamp = targetsTimestamp(endpoints);
    return { kind: 'futured', ...(timestamp === undefined ? {} : { timestamp }), endpoints };
  });
  for (const section of sections.reverse()) content = content.slice(0, section.start) + content.slice(section.end);
  return { content, targets };
}

function drandTargets(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).length !== 1 || !Object.hasOwn(value, 'timestamp')) {
    throw Error('Drand targets must be a single object with a timestamp.');
  }
  const timestamp = targetsTimestamp([value]);
  if (!Number.isSafeInteger(timestamp)) throw Error('Drand requires a timestamp in Unix milliseconds or an ISO date.');
  return { timestamp };
}

async function loadPasswords(env) {
  if (typeof env.PASSWORDS_FILE !== 'string' || !env.PASSWORDS_FILE.trim()) {
    throw Error('PASSWORDS_FILE must specify a .env password file.');
  }
  return parseEnv(await fs.readFile(path.resolve(env.PASSWORDS_FILE), 'utf8'));
}

function serialize(block) {
  return '<template data-encrypted-block>\n' + JSON.stringify(block, null, 2)
    .replace(/</g, '\\u003c').replace(/>/g, '\\u003e').replace(/&/g, '\\u0026') + '\n</template>';
}

async function embedImages(html, session) {
  const replacements = [];
  let depth = 0, count = 0, pixels = 0;
  for (const token of tokenize(html)) {
    if (token.name === 'template') depth += token.closing ? -1 : 1;
    if (depth || token.closing) continue;
    if (token.name === 'source' && token.attrs.srcset) throw Error('Use an img src instead of picture/source srcset.');
    if (token.name !== 'img') continue;
    if (++count > 32) throw Error('Too many images in one content section (maximum 32).');
    if (!token.attrs.src) throw Error('Each image requires a src.');
    const image = await session.load(token.attrs.src, { preserve: Object.hasOwn(token.attrs, 'data-preserve') });
    pixels += image.pixels;
    if (pixels > 8 * 1024 * 1024) throw Error('Images exceed 8 megapixels in one content section.');
    let tag = '<img src="' + image.url + '"';
    for (const name of ['alt', 'width', 'height']) {
      const value = token.attrs[name];
      if (value === undefined || (name !== 'alt' && !/^[1-9]\d{0,3}$/.test(value))) continue;
      if (name !== 'alt' && Number(value) > 4096) continue;
      tag += ' ' + name + '="' + value.replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;') + '"';
    }
    replacements.push({ start: token.start, end: token.end, tag: tag + '>' });
  }
  for (const r of replacements.reverse()) html = html.slice(0, r.start) + r.tag + html.slice(r.end);
  return html;
}

async function compileHTML(html, { env = process.env, passwords, sourceDir = process.cwd() } = {}) {
  passwords = passwords ?? await loadPasswords(env);
  const roots = templateTree(html);
  const images = imageSession(sourceDir);
  let count = 0, usesDrand = false;
  async function transform(nodes, start, end, depth = 0, inertParent = false) {
    let output = '', cursor = start;
    for (const node of nodes) {
      output += html.slice(cursor, node.start);
      const attrs = node.attrs;
      const marked = Object.hasOwn(attrs, 'data-encrypted-block');
      if (!marked) {
        output += html.slice(node.start, node.end) + await transform(node.children, node.end, node.contentEnd, depth, true) + html.slice(node.contentEnd, node.closeEnd);
      } else {
        if (inertParent) throw Error('Encrypted blocks cannot be inside an unmarked inert template.');
        if (++count > MAX_BLOCKS || depth > MAX_DEPTH) throw Error('Block count or nesting depth exceeds loader limits.');
        const elementId = attrs.elementid;
        if (!elementId || !elementId.trim()) throw Error('Authoring template requires elementId.');
        const nestedContent = await transform(node.children, node.end, node.contentEnd, depth + 1);
        const extracted = extractTargets(nestedContent);
        let targets = extracted.targets;
        const content = await embedImages(extracted.content, images);
        const name = attrs.password;
        if (typeof name !== 'string' || !name.trim()) throw Error(`Template ${elementId} requires a password lookup name.`);
        if (!Object.hasOwn(passwords, name)) throw Error(`Password lookup missing for ${elementId}.`);
        const password = passwords[name];
        if (typeof password !== 'string' || !password.trim()) throw Error(`Password is empty for ${elementId}.`);
        if (content.length > MAX_SIZE) throw Error(`Content for ${elementId} exceeds the loader size limit.`);
        for (const target of targets) {
          if (target.kind === 'drand') {
            Object.assign(target, await encryptDrandPassword(password, target.timestamp));
            usesDrand = true;
          }
        }
        const block = { elementId, targets, ...await encrypt(content, password) };
        const rendered = serialize(block);
        if (rendered.length > MAX_SIZE) throw Error(`Encrypted block ${elementId} exceeds the loader size limit.`);
        output += rendered;
      }
      cursor = node.closeEnd;
    }
    return output + html.slice(cursor, end);
  }
  try { return { html: await embedImages(await transform(roots, 0, html.length), images), count, usesDrand }; }
  finally { await images.close(); }
}

function inlineLoader(source, css, { usesDrand = false } = {}) {
  if (usesDrand) {
    const bundled = require('esbuild').buildSync({
      entryPoints: [path.join(__dirname, 'drand.cjs')], bundle: true, write: false,
      platform: 'browser', format: 'iife', globalName: 'DrandModule', target: 'es2020'
    }).outputFiles[0].text;
    source = source.replace('const DRAND = null;', () => 'const DRAND = (() => {' + bundled + '; return DrandModule; })();');
  }
  const marker = 'const FRAME_PICO = null;';
  if (source.includes(marker)) {
    css = (css ?? readFileSync(path.join(__dirname, '..', 'assets', 'picocss2.1.1.css'), 'utf8'))
      .replace(/\r\n?/g, '\n').replace(/^\uFEFF?@charset\s+["'][^"']+["'];/i, '');
    if (/<\/style/i.test(css)) throw Error('Pico stylesheet contains an unsafe closing style tag.');
    css += PAGE_LAYOUT_CSS;
    const hash = 'sha256-' + createHash('sha256').update(css).digest('base64');
    source = source.replace(marker, () => 'const FRAME_PICO = ' + JSON.stringify({ css, hash }) + ';');
  }
  const { code } = minify_sync(source, {
    compress: true,
    mangle: true,
    format: { inline_script: true, comments: false }
  });
  return {
    tag: '<script>' + code + '</script>',
    originalBytes: Buffer.byteLength(source),
    minifiedBytes: Buffer.byteLength(code),
    cspHash: 'sha256-' + createHash('sha256').update(code).digest('base64')
  };
}

function attachLoader(html, loaderTag) {
  const bodyEnd = tokenize(html).findLast(token => token.name === 'body' && token.closing)?.start ?? html.length;
  return html.slice(0, bodyEnd) + '\n' + loaderTag + '\n' + html.slice(bodyEnd);
}

function attachPico(html, css) {
  // @charset is for standalone stylesheets; preserve the bundled license.
  css = css.replace(/^\uFEFF?@charset\s+["'][^"']+["'];/i, '');
  if (/<\/style/i.test(css)) throw Error('Pico stylesheet contains an unsafe closing style tag.');
  const style = '<style data-pico-css>\n' + css + PAGE_LAYOUT_CSS + '\n</style>';
  const tokens = tokenize(html);
  const replacements = [];
  let templateDepth = 0;
  for (let i = 0; i < tokens.length; i++) {
    const token = tokens[i];
    if (token.name === 'template') templateDepth += token.closing ? -1 : 1;
    if (templateDepth || token.closing) continue;
    if (token.name === 'style' && Object.hasOwn(token.attrs, 'data-pico-css')) {
      replacements.push({ start: token.start, end: tokens[i + 1].end });
    } else if (token.name === 'link' && /(?:^|\s)stylesheet(?:\s|$)/i.test(token.attrs.rel || '') &&
      /(?:^|\/)picocss2\.1\.1\.css(?:[?#].*)?$/.test(token.attrs.href || '')) {
      replacements.push({ start: token.start, end: token.end });
    }
  }
  for (const r of replacements.reverse()) html = html.slice(0, r.start) + html.slice(r.end);
  const updated = tokenize(html);
  const head = updated.find(token => token.name === 'head' && !token.closing);
  if (head) return html.slice(0, head.end) + '\n' + style + html.slice(head.end);
  const root = updated.find(token => token.name === 'html' && !token.closing);
  // Full pages without an explicit head get one; fragments get the style first.
  if (root) return html.slice(0, root.end) + '\n<head>' + style + '</head>\n' + html.slice(root.end);
  const doctype = /^\s*<!doctype[^>]*>/i.exec(html);
  const offset = doctype ? doctype[0].length : 0;
  return html.slice(0, offset) + '\n' + style + '\n' + html.slice(offset);
}

async function buildFile(filename, { buildDir = path.resolve('build'), env = process.env } = {}) {
  const input = path.resolve(filename);
  if (!/\.html?$/i.test(input)) throw Error('Input must be an .html or .htm file.');
  const output = path.join(path.resolve(buildDir), path.basename(input));
  if (output === input) throw Error('Refusing to overwrite the source file.');
  const result = await compileHTML(await fs.readFile(input, 'utf8'), { env, sourceDir: path.dirname(input) });
  const css = await fs.readFile(path.join(__dirname, '..', 'assets', 'picocss2.1.1.css'), 'utf8');
  const loader = inlineLoader(await fs.readFile(path.join(__dirname, 'time-locked-html.js'), 'utf8'), css, { usesDrand: result.usesDrand });
  const html = attachPico(attachLoader(result.html, loader.tag), css);
  await fs.mkdir(buildDir, { recursive: true });
  const temporary = output + '.' + randomBytes(6).toString('hex') + '.tmp';
  try { await fs.writeFile(temporary, html); await fs.rename(temporary, output); }
  finally { await fs.rm(temporary, { force: true }); }
  return { output, count: result.count, ...loader };
}

module.exports = { compileHTML, buildFile, templateTree, resolveTargets, inlineLoader };
if (require.main === module) {
  if (process.argv.length !== 3 || process.argv[2] === '--help') {
    console.log('Usage: node src/build.cjs <page.html>\nSet PASSWORDS_FILE to a .env file. Writes build/<page.html> with its minified loader and Pico CSS embedded.');
    process.exitCode = process.argv[2] === '--help' ? 0 : 1;
  } else {
    buildFile(process.argv[2]).then(result => {
      console.log(`Built ${result.count} block(s): ${result.output}`);
      console.log(`Embedded loader: ${result.originalBytes} -> ${result.minifiedBytes} bytes`);
      console.log(`Inline CSP hash: '${result.cspHash}'`);
    }).catch(error => { console.error(`Build failed: ${error.message}`); process.exitCode = 1; });
  }
}
