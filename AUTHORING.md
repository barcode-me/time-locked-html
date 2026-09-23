# Authoring and compiling pages

Install build dependencies with `npm ci`, then run the Node.js compiler from your project directory:

```sh
PASSWORDS_FILE=./passwords.env node src/build.cjs page.html
```

It writes `build/page.html` with the minified loader embedded. Source HTML must not include the loader: compilation always adds it before the closing body tag (or at the end of a fragment), without detecting, rewriting or removing existing script tags. Source files remain unchanged. Existing output is replaced only after compilation succeeds. The bundled `assets/picocss2.1.1.css` is embedded in a `<style data-pico-css>` element in the output head, preserving its license. Existing references to that file or previously embedded Pico styles are replaced to avoid duplicates. Copy other public assets separately if needed. Use Node 18+.

## Single-file build

```sh
PASSWORDS_FILE=./passwords.env node src/build.cjs html/page.html
```

This invokes the same build script shown above, including the minified loader in an inline `<script>` in `build/page.html`. No loader file is written by this command, and older build artifacts are left alone. Pico CSS is also embedded. Images referenced by `<img src>` are optimized and embedded too; other page resources are not bundled.

JavaScript minification uses [Terser](https://terser.org/docs/api-reference/), installed as a development dependency. Compression and local-name mangling are enabled, with inline-script escaping handled by Terser. Public property names remain unchanged. Password and futured pages have no browser library dependencies. Pages containing drand targets bundle tlock-js and its dependencies with esbuild, then minify the combined loader with Terser. No library CDN is needed. Other page scripts and HTML whitespace are not minified.

A standalone demo build:

```sh
PASSWORDS_FILE=./passwords.env.example node src/build.cjs html/authoring-example.html
```

The output reports the loader's before/after size and a CSP hash for the exact embedded script. If your host page enforces CSP that forbids inline scripts, allow that hash in its `script-src` policy. The restrictive CSP inside decrypted content frames remains separate and unchanged. A single-file build removes the loader download; futured password endpoints still require network access.

## Blocks and manual password entry

Place plaintext HTML inside a marked template:

```html
<template data-encrypted-block
          elementId="private-content"
          password="PAGE_PASSWORD">
  <targets data-manual></targets>
  <targets data-dns data-domain="example.com" data-txt-key="pass"></targets>
  <h2>Private section</h2>
  <p>This HTML will be encrypted.</p>
</template>
```

Set `PASSWORDS_FILE` to the path of a `.env` file, resolved relative to the current working directory:

```dotenv
PAGE_PASSWORD="your private password"
FUTURED_PASSWORD="the password returned by your service"
```

Every template, including nested templates, requires a `password` attribute naming an entry in this file. The attribute is a lookup key, not the password value. Missing files, missing keys, empty attributes, empty values and whitespace-only values fail compilation. Nonempty values retain their exact parsed whitespace. The file is parsed with `dotenv.parse`, without importing values into the process environment or expanding variables. The compiler does not fall back to other environment variables.

Password files are excluded by `.gitignore`; `passwords.env.example` contains demonstration values. Neither the file, lookup attributes nor password values are copied into the generated page. Keep authoring content and credentials outside the publicly served build directory.

A runnable source example is [authoring-example.html](html/authoring-example.html). For a local demonstration only:

```sh
PASSWORDS_FILE=./passwords.env.example node src/build.cjs html/authoring-example.html
```

Open `build/authoring-example.html` and use `demo-only-change-me` for both nested password forms. A browser allowing Web Crypto for local files can open it directly; otherwise serve the build directory from localhost.

## Choosing how to obtain the password

Blocks have no `type` attribute. Each block requires `password="ENV_KEY"` and at least one `<targets>` element. All target choices obtain the same password; each `<targets>` element creates one radio button in source order. The first is active by default. Only selecting another radio button changes the active choice; polling, errors and date changes never switch choices automatically.

```html
<template data-encrypted-block elementId="private" password="PAGE_PASSWORD">
  <targets data-manual></targets>
  <targets data-drand>{"timestamp":"2030-01-01T00:00:00Z"}</targets>
  <targets data-futured>[{"url":"https://example.com/password","namespace":"example","timestamp":"2030-01-01T00:00:00Z"}]</targets>
  <p>One encrypted payload, four ways to obtain its password.</p>
</template>
```

`data-manual` must be empty (whitespace is allowed) and displays a password field. A selected `data-dns` choice queries a public DNS TXT record. A selected `data-futured` choice tries its HTTP endpoint array in order. A selected `data-drand` choice recovers the wrapped password at its scheduled time. Multiple choices of the same kind are allowed. Different choices can have different release dates; timestamps only need to agree among endpoints within one futured choice.

## DNS TXT password targets

Use an empty `<targets data-dns data-domain="example.com" data-txt-key="pass"></targets>` inside the encrypted template. Publish a TXT record at that exact domain containing `pass=YOUR_PASSWORD`, where `YOUR_PASSWORD` equals the value in the build's password file. A record can contain several pairs, such as `key1=value1; pass=YOUR_PASSWORD; key3=value3` or `key1=value1 pass=YOUR_PASSWORD`. Semicolons or whitespace separate pairs, and `=` separates each key from its value. The key must match `data-txt-key` exactly. Delimiter characters and whitespace at the end of a value are removed, so avoid passwords ending in those characters. The compiler stores only the domain and key in the block. The browser queries Cloudflare DNS over HTTPS and then Google Public DNS if the first answer is missing, unavailable, or does not decrypt the block. TXT strings split into quoted DNS chunks are joined before matching. The active choice retries after 30 seconds. Public DNS caches may delay changes, and the published password is visible to anyone who queries the record. The resolver endpoints must be reachable from the browser.

See [dns-example.html](html/dns-example.html) for a complete template with a manual fallback. Replace its example domain with one you control before publishing the TXT record.

Inactive choices never fetch or retry. Switching aborts outstanding network requests, clears the password form, resets the selected choice's retry timer, and prevents stale decryption results from modifying the page. Choosing a future target displays its date and waits. The controls disappear when the block unlocks.

A complete example is [targets-example.html](html/targets-example.html). Each choice is an alternative access path: a manual password or earlier service release can unlock the content before a drand date.

## Futured password targets

A `<targets data-futured>` element contains a nonempty JSON array of HTTP endpoints. Every endpoint must define a valid `timestamp` and a nonempty string `namespace`, either on the endpoint object or in its JSON request body. Missing or invalid values fail the build, including on fallback endpoints. Put it outside any child templates so it belongs to the intended block:

```html
<template data-encrypted-block
          elementId="scheduled-content"
          password="FUTURED_PASSWORD">
  <targets data-futured>
  [{
    "url": "http://localhost:8000/hash",
    "method": "POST",
    "headers": {
      "Content-Type": "application/json",
      "Accept": "text/plain; charset=utf-8"
    },
    "body": "{\"namespace\":\"foo\",\"timestamp\":10000000000}"
  }]
  </targets>
  <h2>Scheduled content</h2>
  <p>This content becomes accessible when a target returns its password.</p>
</template>
```

Array order determines endpoint order. The compiler removes `<targets data-futured>` from the plaintext HTML and writes the resolved array to that choice's `endpoints` field. Each nested block has its own targets; child targets are never used by the parent.

To preserve the runtime's readable unlock date and no-early-request behavior, the compiler reads `timestamp` from a JSON request body's top-level property, or from a target object's own `timestamp` property (useful for GET requests). It copies that date into the generated futured choice's `timestamp` in Unix milliseconds without modifying the request values. Numbers and numeric strings mean Unix milliseconds; ISO date strings are also accepted. Every specified timestamp within one futured choice must identify the same instant; conflicting or invalid dates fail compilation. The loader also reads these timestamps directly from endpoint metadata or JSON request bodies. While this choice is active, it displays the release date and waits before requests and decryption; it rechecks the date after a password response in case the clock moved backward. A missing timestamp fails the build. The target-level `timestamp` is loader metadata and is not automatically added to the HTTP request.


## Drand time locks

```html
<template data-encrypted-block elementId="scheduled" password="DRAND_PASSWORD">
  <targets data-drand>
    {"timestamp":"2030-01-01T00:00:00Z"}
  </targets>
  <p>This content unlocks through drand.</p>
</template>
```

`<targets data-drand>` requires a single JSON object with a `timestamp`: Unix milliseconds or an ISO date with timezone. The timestamp must be in the future at build time. Unmarked target tags and tags with multiple target attributes are rejected. A drand choice can coexist with manual and futured choices in the same block.

The HTML uses the existing AES-GCM encryption with the password from `PASSWORDS_FILE`. Only that password is additionally encrypted using [tlock-js](https://github.com/drand/tlock-js) and quicknet's pinned public key. Building requires no drand network requests. The compiler removes the authoring targets tag and persists a `kind: "drand"` entry in the compiled block's `targets` array containing `timestamp`, `round`, `chainHash` and `encryptedPassword`. The latter is Base64-encoded UTF-8 AGE armored ciphertext, safe to embed in HTML JSON; it is not the plaintext password.

The selected round is the first quicknet round at or after the requested timestamp, with up to three seconds of rounding. The browser displays its scheduled date, waits without requesting beacons, then retrieves and verifies the public beacon before recovering the password and decrypting the HTML. Failed attempts retry after 30 seconds. Network availability may delay unlocking. The existing isolated iframe renderer is unchanged.

Use a unique, strong random password for each release time. A known password, or one reused in an earlier release, can decrypt the HTML without waiting for drand. The demonstration password file is public and is not suitable for real secrets.

The build includes the drand bundle only when it finds a drand target, including those nested inside encrypted blocks. A page built without it cannot process drand blocks added later. The bundle needs browser BigInt support and network access to `https://api.drand.sh`; the iframe itself still has no network or script permissions.

Try `PASSWORDS_FILE=./passwords.env.example npm run build -- html/drand-example.html` after choosing a future date and a private password.

## Obtaining the encryption password

All encryption passwords are loaded from the file selected by `PASSWORDS_FILE`. Compilation never contacts target endpoints. Targets are used only by the browser to obtain decryption passwords when the active target is eligible. For a futured choice, ensure at least one service will return exactly the password stored under its lookup key.

The file is read once per compilation. All templates share its entries, and nested templates may select different passwords.

## Nested blocks and output format

Nested marked templates are compiled from the inside out. The inner JSON block becomes part of the outer plaintext before the outer block is encrypted. Nested passwords may differ. No source JavaScript is needed to register blocks.

Output templates contain only JSON:

```html
<template data-encrypted-block>
{
  "targets": [{"kind":"manual"}],
  "elementId": "private-content",
  "salt": "...",
  "iv": "...",
  "data": "..."
}
</template>
```

AES-256-GCM, PBKDF2-SHA-256 with 600,000 iterations, random 16-byte salts and random 12-byte IVs match the browser loader. Every build uses fresh randomness. JSON is escaped for safe embedding in templates.

Write balanced, explicit `<template>...</template>` tags; self-closing templates and encrypted blocks inside unmarked inert templates are rejected. The source tokenizer handles comments, quoted attributes and raw-text elements such as scripts/styles/textareas; it preserves other HTML verbatim rather than applying browser error recovery. Use well-formed authoring HTML, not malformed or adversarial HTML. Source code outside encrypted templates remains public and is not sanitized by the compiler.

The compiler checks the loader's count, nesting and payload-size limits. Rendering still follows the runtime's read-only policy: content-provided styles and controls inside encrypted content will not appear, and nested blocks render below their parent's frame. See [SECURITY.md](SECURITY.md).

Run compiler checks with `node --test test/compile.test.cjs`. The separate `node --test test/test.cjs` suite runs compiler output in real Chrome.

Run build/minification checks with `node --test test/build.test.cjs`. The Chrome suite also exercises the minified inline loader.

Pico styles the host page, loader controls and isolated content frames. The compiler pins the exact bundled CSS with a SHA-256 CSP hash inside each frame; other stylesheets and all inline style attributes remain blocked. Custom host-page styles follow Pico and can override its defaults.

## Images

```html
<template data-encrypted-block elementId="photos" password="PAGE_PASSWORD">
  <targets data-manual></targets>
  <h2>Photos</h2>
  <img src="../assets/photo.jpg" alt="A photograph">
  <img src="https://example.com/diagram.png" alt="A diagram">
</template>
```

The compiler handles every `<img src>` in rendered source content, including nested encrypted blocks and public content outside blocks. Local paths resolve relative to the source HTML file; remote URLs must be absolute HTTP(S). Existing Base64 PNG/JPEG/GIF/WebP data URLs also work. Inert unmarked templates are not processed. CSS background images are not downloaded. Supply `src` rather than responsive-only images: `srcset` is removed, and `<source srcset>` is rejected.

Remote images are downloaded into a unique OS temporary directory, processed, and removed on success or failure. Repeated sources are cached for that compilation. Downloads have a 10-second timeout and a 20 MiB per-image / 100 MiB aggregate download limit. The compiler makes these image requests without cookies; it still never requests passwords from targets. Only use trusted authoring sources, since image URLs and local paths are build inputs.

By default, Sharp validates and decodes PNG, JPEG, GIF and WebP inputs (up to 32 megapixels), applies orientation, resizes to fit 1600 × 1600 without enlarging smaller images, and strips metadata. Output is WebP at quality 80, retrying at 65 and 50 if necessary to stay below 512 KiB. Transparency is retained. Animated inputs use their first frame. Failure to download, decode or meet limits stops compilation without replacing the previous output. The resulting data URL is inserted before encryption, so private images remain inside their encrypted block.

Add `data-preserve` to embed the original image bytes without resizing, rotating, recompressing, stripping metadata, or flattening animation:

```html
<img src="../assets/photo.jpg" data-preserve alt="Original photograph">
```

The attribute is enabled by its presence, regardless of its value. It works with local files, HTTP(S) URLs and existing Base64 images. Preserved images must already meet the 512 KiB, 4096-pixel side and 4-megapixel limits; compilation fails instead of optimizing an oversized original. Format and decoding validation still apply. Metadata, including any location information, is retained. This controls compilation; normal browser layout, explicit width/height attributes and Pico's responsive image styling still apply.

Only `src`, escaped `alt`, and validated positive `width`/`height` attributes (up to 4096) are retained. Event handlers and other attributes are removed. The runtime independently checks Base64 format, MIME signatures and decoded dimensions, rejecting SVG, non-raster data and external URLs. It requires `createImageBitmap`; undecodable or unsupported images are omitted. Each image is limited to 512 KiB, 4096 pixels per side and 4 megapixels; a content section allows up to 32 images and 8 megapixels total. The block's existing encrypted-size limit still applies, including Base64 overhead. The iframe CSP uses `img-src data:`; Pico-only CSS and the empty sandbox remain in effect.

Run image-processing tests with `npm run test:unit` and rendering/CSP checks with `npm run test:browser`.
