_NOTICE: I am not a cryptographer. Use this tool under your own responsibility, this is an experimental project._

# Time-locked HTML

A simple tool to build time-locked HTML documents for inheritance and emergency purposes.

## How is this useful for inheritance or emergencies?

This tool allows you to encrypt HTML content in a way that aims to only make it feasibly possible to decrypt it at a target date. This allows to design dead man switches for inheritance or emergencies. Services that claim to provide this service charge several hundred dollars per year and they are not always end to end encrypted or don't use zero knowledge ecryption.

You can use a secure device (preferably offline) to create the encrypted HTML file with this tool with a target date of 6 months from current date. Then you can use regular reputable email providers to schedule an email with the same target date to a list of recipients and attach the encrypted HTML file. While you are still alive and around with access to your email accounts you can simply push the date into the future by manually deleting the scheduled emails, encrypting a new HTML file with a new target date of 6 months, and scheduling new emails with the same target date and the new encrypted HTML.

The result is that when you are no longer alive or around the email will be automatically sent to your recipients at the target date. For redundancy make sure you use at least two email providers just in case one of them fails.

## How does time lock encryption works?

This project offers 4 different techniques and only one of them is technically a time lock.

First, manual password decryption. With this mode the user opens the HTML page and the user is prompted to enter a password manually. This is not time lock at all, but if you combine this with password manager emergency contact access and use a truly random and long password then it practically becomes a time lock. For example, maybe your children or spouse can only access your password manager via emergency contact when you are no longer around. So they could only access the password to decrypt the HTML at that future date. In this simple scenario you don't even worry about a specific target date it just happens when they access the password manager.

Second mode is via the drand network. This is a somewhat new network it has been in operation for a few years, and it is a coallition of companies and organizations that distribute trust among them to avoid a situation where a single institution colludes to break the rules of the system. The network essentially allows you to hide a decryption key until a future date. Only if the majority of the nodes agree that the date is in the past the decryption key is relased to the public. Of course there is trust involved in this project but at least it is distributed among several institutions. The risks of course is that there could be problems in the future like security braches or lack of maitenance of the project and the network becoming unreliable or unavailable. For this reason I suggest that for critical flows use this in conjuction with another mode.

Third mode is a self-hosted service known as [futured](https://github.com/barcode-me/futured). This service is simple and allows you to query for time-based hashes that can be used as decryption passwords. You can self host it in a couple of cloud providers or on-promise and query it similar to the drand network only if the target time is in the past the password will be returned.

Fourth mode is TXT DNS records. An encrypted block can specify a target domain and a key to lookup within the TXT records. This key will contain the password to decrypt the content. The beauty of this approach is that it can run in a server not exposed to the public and therefore it is a lot more secure. For fault tolerance it is recommended to use at least two domains as targets from different providers that support changing TXT records via an API like AWS and GCP. 

The good news is that you don't have to choose one. You can choose multiple. What you choose is up to you. The drand network is more convinient and as long as it remains reliable it is the most secure option. But only time will tell. On the other hand futured is more DIY so if something happens to the services hosting it while you are not around, it can lead to the inability to decrypt the HTML file. This is why redundant providers are recommended. Then there is DNS mode which can be a lot easier to secure since you can setup multiple cheap and secure devices with internet access that perform a background job to check if it is time to publish the password to DNS.

Finally password is the simplest of them all, and it is less risky in the sense that you don't depend in any 3rd party service to remain available. As long as the user has the HTML file and the password they can decrypt the HTML files. Of course how you secure that password and how you hand it over to the recipient is up to you.

## Can you garantee it can only be decrypted in the future?

The truth is that like everything in life this tool might not work in all scenarios. The drand network might get compromised, your password manager might fail and disclose passwords to the world. The futured service might be hacked and the secrets disclosed along with the decryption keys. Maybe AES encryption gets broken in the near future. It might even be possible that some obscure bug causes a vulnerability that makes it possible to decrypt the files without waiting for the target date. I don't think the tool has such a problem, but history has shown us that black swan events happen when less expected. This tool cannot garantee 100% the files can only be decrypted in the future, but I think it does a great job.

# Introduction

To build a single HTML file with encrypted blocks and its minified loader embedded, run `node src/build.cjs html/page.html`. Output goes to `build/page.html`, including the bundled Pico CSS inline. Do not include a loader script in authoring HTML; compilation always appends it. See [AUTHORING.md](AUTHORING.md) for template attributes, inline targets, passwords and nested examples.

Install build dependencies with `npm ci`. Set `PASSWORDS_FILE` to a `.env` file of named passwords; each authoring template selects one with its required `password="NAME"` attribute. Then use the package scripts:

```sh
PASSWORDS_FILE=./passwords.env npm run build -- html/authoring-example.html
npm test
npm run test:unit
npm run test:browser
```

`npm test` runs all tests, including Chrome browser checks. `test:unit` runs without a browser; `test:browser` requires Chrome (or `CHROME_BIN`).

The browser runtime is `src/time-locked-html.js`. Include it as a classic browser script. For manual and futured targets it can run directly; drand targets require the bundled build. Serve over HTTPS or localhost for Web Crypto.

```html
<div id="secret"></div>
<script src="../src/time-locked-html.js" defer></script>
```

Embed JSON in `<template data-encrypted-block>` elements. The loader scans the document every second and immediately after each decryption, so decrypted HTML can contain additional block templates without scripts. It deduplicates identical JSON text (ignoring surrounding whitespace) and processes each block independently. There is no global block array. For top-level blocks, a sandboxed iframe replaces the contents of `elementId`; missing elements are appended to the body. Nested blocks get separate containers below their parent frame, regardless of their `elementId`, so they cannot overwrite other page content.

The debug panel is enabled by default in the bottom-right corner. It shows the number of unique discovered blocks, including nested and invalid entries (up to the block limit). Expand a block to inspect its formatted JSON; malformed JSON is shown as raw text. The panel updates during each scan and can be collapsed using its heading. To disable it, set `window.TimeLockedHTMLDebug = false` before loading the script or at runtime. Set it to `true` to show it again; runtime changes take effect on the next scan. The inspector displays the supplied block data, including any headers or request bodies.

```html
<template data-encrypted-block>
{
  "elementId": "secret",
  "salt": "BASE64_SALT",
  "iv": "BASE64_IV",
  "data": "BASE64_CIPHERTEXT_AND_GCM_TAG",
  "targets": [
    { "kind": "manual" },
    {
      "kind": "futured",
      "timestamp": "2027-01-01T00:00:00Z",
      "endpoints": [
        { "url": "https://example.com/password", "namespace": "foo", "timestamp": 1798761600000 },
        {
          "url": "https://example.com/hash",
          "method": "POST",
          "headers": { "Content-Type": "application/json", "Accept": "text/plain; charset=utf-8" },
          "body": "{\"namespace\":\"foo\",\"timestamp\":1798761600000}"
        }
      ]
    }
  ]
}
</template>
```

Templates contain strict JSON, not JavaScript expressions. When generating their text, escape `<`, `>`, and `&` as JSON Unicode escapes so values cannot be parsed as HTML or close the template:

```js
const templateJSON = JSON.stringify(block)
  .replace(/</g, "\\u003c")
  .replace(/>/g, "\\u003e")
  .replace(/&/g, "\\u0026");
```

Use this text between the template tags when generating HTML. The same format works inside HTML before encryption. Templates remain invisible; their destination elements show the unlock UI and decrypted content. Templates are discovered in the current document and extracted from each decrypted HTML fragment before rendering. Templates inside other inert templates, shadow roots, or iframe documents are not traversed. Removing a template does not cancel a registered job. Identical templates do not rerun completed jobs.

Replace the Base64 placeholders with actual encrypted values. Blocks have no type or global timestamp. Their ordered `targets` array lists password-retrieval choices, each with a `kind`: `manual`, `dns`, `futured` or `drand`. The first radio button is selected initially; only the user changes the selection. All choices unlock the same AES payload with the same password.

A manual choice displays a password form. A DNS choice has `domain` and `txtKey` fields and looks for a TXT value beginning with `txtKey=` using Cloudflare and Google DNS over HTTPS; see [DNS authoring](AUTHORING.md#dns-txt-password-targets). A futured choice has an `endpoints` array and a required `timestamp` (Unix milliseconds or an ISO date). Its date is displayed in the user's locale; no request is made before it. Only endpoints inside the active futured choice run sequentially until decryption succeeds. Failed rounds retry after 30 seconds without selecting another choice. HTTP requests time out after 10 seconds, including response reading.

Each authored futured endpoint must provide a valid `timestamp` and a nonempty `namespace` on the endpoint or in its JSON body; otherwise the build fails. HTTP endpoints are objects with `url`, `method` (default GET), `headers`, and a string `body`. GET/HEAD omit the body. Default responses are exact plain-text passwords (no trimming); `responseType: "json"` accepts a JSON string or `{ "password": "..." }`. Endpoints must permit browser CORS requests when cross-origin. Requests omit cookies and HTTP authentication credentials.

Drand choices contain `kind: "drand"`, `timestamp`, `round`, `chainHash`, and `encryptedPassword`. Each wraps the same block password with tlock-js for a future quicknet round; see [drand authoring](AUTHORING.md#drand-time-locks). Drand dependencies are bundled only for pages containing drand targets, including nested ones. Switching choices aborts the old network requests and ignores their pending results. Inactive targets never fetch or retry.

Encryption uses PBKDF2-SHA-256 with 600,000 iterations, AES-256-GCM, a 16-byte salt, and a 12-byte IV. The plaintext is UTF-8 HTML. Blocks contain Base64-encoded `salt`, `iv`, and `data` fields directly; `data` contains the ciphertext followed by the authentication tag.

Use a distinct `elementId` per block. Blocks are immutable jobs: to correct a malformed entry, add a corrected template or replace its content with corrected JSON. Malformed blocks are logged once and do not stop other blocks. `TimeLockedHTML.scan()` requests an immediate scan; `TimeLockedHTML.decrypt(password, payload)` exposes the raw UTF-8 decryption helper.

Decrypted HTML is parsed in a detached, inert template and rebuilt as read-only formatting inside an iframe with an empty `sandbox` attribute. A CSP placed before the content allows only the compiler-bundled Pico CSS by its exact SHA-256 hash and blocks scripts, other CSS, external images, other resources, forms, and base URL changes. The renderer preserves paragraphs, headings, lists, emphasis, quotes, code and basic tables, with no content-provided attributes except validated image attributes. Links become non-clickable text. Styles, scripts, controls, forms, embedded documents, SVG, MathML, custom elements and other unsupported elements are removed with their contents. Original styling, IDs and interactive behavior are intentionally not preserved.

Frames are full-width, 320px tall, and scroll for longer content. They do not have same-origin access, so the parent does not inspect them or automatically size them to their contents. Password forms remain in the parent page. Extracted nested templates are registered there before subsequent polling; no decrypted template or raw markup is attached to the parent document.

Limits: 100 unique block entries per loader lifetime (including invalid entries), eight levels of nested blocks below the root, 2,097,152 JavaScript string code units per block JSON/decrypted HTML, and 100 levels of displayed formatting. Entries beyond the block limit are ignored; invalid/oversized entries are logged, and excessive display nesting is omitted. These are bounded resource safeguards, not a complete denial-of-service defense. See [SECURITY.md](SECURITY.md) for remaining metadata and endpoint risks.

Futured timestamps are client-side timing gates; enforce password release time on the server. Drand additionally wraps the password for a future round. Any alternative choice that exposes the password earlier can unlock the same block sooner.

Run the real-browser checks with `node --test test/test.cjs` (Node 18+ and Chrome). The default browser path is the macOS Chrome installation; set `CHROME_BIN` for another installation. Tests use a temporary browser profile and local HTTP server, use installed build dependencies, and clean up afterward.

Images in authoring HTML can use local paths, HTTP(S) URLs, or Base64 data URLs. Compilation uses Sharp to resize and optimize them as embedded WebP images before encryption, and also embeds images outside encrypted blocks. Add `data-preserve` to an image to embed its original bytes without optimization, subject to the same output safety limits. Remote downloads use temporary storage that is removed after success or failure. Iframes allow only validated Base64 PNG/JPEG/GIF/WebP images, keeping external image requests blocked. See [AUTHORING.md](AUTHORING.md#images) for limits and optimization settings.
