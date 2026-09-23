# Decrypted HTML security

## Implemented boundaries

Decrypted HTML never enters the live parent DOM. The loader parses it in a detached template, extracts block JSON, and reconstructs a small set of HTML formatting tags with escaped text and a restricted attribute set for validated embedded raster images. Unsupported elements and their subtrees are dropped; links retain their text/allowed formatting but lose navigation. This is a deliberately restricted renderer, not a general-purpose HTML sanitizer.

Each rendered document uses `iframe sandbox=""`, without script, same-origin, form, popup, download or top-navigation allowances. A CSP precedes all displayed content:

```
default-src 'none'; script-src 'none'; style-src 'sha256-PICO_CSS_HASH'; style-src-attr 'none'; img-src data:; form-action 'none'; base-uri 'none'; object-src 'none'; frame-src 'none'
```

Filtering removes navigation markup and controls too: sandbox/CSP alone do not prevent every native interaction or same-frame navigation. Nested templates are extracted before rendering, registered by the parent loader, and excluded from the frame. Their destination containers are newly created below the parent frame; nested metadata cannot select arbitrary existing page elements. The loader retains destination references through decryption.

Block count, nesting depth and input/display size are bounded as documented in README.md. Drand builds include tlock-js and its dependencies in the host-page loader; other builds need no browser library dependencies; compilation uses Sharp for raster-image optimization. The browser tests exercise actual inert parsing, iframe isolation, filtering, nested extraction, destination collisions, and absence of unexpected HTTP requests, alongside the decryption workflow.

## Remaining risks and trust requirements

- **Password endpoints are still active parent-page requests.** The iframe policy does not constrain the loader's `fetch`. Nested blocks may specify HTTP(S) endpoints in their password-retrieval choices, methods, headers and bodies; origins and redirects are not allowlisted. Cookies are omitted, but explicit headers/bodies and access to local services still matter. Only the selected target choice is requested; that is not an endpoint authorization policy. Trust block metadata or add an application-specific endpoint policy before accepting arbitrary publishers.
- **Encryption does not establish publisher identity.** AES-GCM authenticates ciphertext under the derived key, but `elementId` and `targets` are not authenticated as associated data. Use signatures over the complete envelope if trusted provenance is required.
- **Top-level templates belong to the trusted host page.** They still select existing destination IDs. Only nested destinations are forced into new containers. Host-page scripts, extensions, and arbitrary markup already present outside encrypted blocks are outside this boundary.
- **Readable content can still deceive.** Plain text can contain misleading instructions. Frames do not authenticate claims made in the content.
- **Resource safeguards are limited.** Parsing/decryption happens before some limits can be checked, endpoint response lengths are not capped, and up to 100 retained jobs can retry. Network timeouts and size/depth limits reduce risk without eliminating denial of service.
- **Debug JSON is visible.** The enabled inspector includes request headers/bodies and nested metadata. Avoid secrets in metadata and disable debug UI for production. Hiding it does not hide data from trusted parent-page scripts.
- **Futured time gating is local.** Enforce release times at the password service. Drand wraps the password for a future quicknet round, using a pinned public key and verified beacons. This relies on the drand threshold network and tlock cryptography; a known, weak or reused password bypasses that protection. Use a unique random password per release. Multiple choices share the password: manual access or an earlier service/round can bypass a later choice's date. Drand requests originate in the host page, use a fixed quicknet endpoint, omit credentials, reject redirects and time out after 10 seconds.

Real Chrome checks run on localhost. This is not a full browser security audit; Firefox, Safari and local-file rendering have not been verified by this suite. Do not loosen sandbox permissions or reuse reconstructed HTML in the parent DOM without reviewing the boundary.

## References

- [MDN: iframe sandbox](https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Elements/iframe#sandbox)
- [MDN: CSP default-src](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/default-src)
- [OWASP: XSS prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)

## Embedded images

By default, the compiler decodes and re-encodes raster inputs with Sharp, removing metadata and enforcing input/output limits. Images marked `data-preserve` retain their original bytes and metadata (including possible location data); format, decoding and output limits still apply. Remote downloads are staged in a temporary directory that is cleaned up; authoring image URLs and local file paths must be trusted. The iframe filter allows only Base64 PNG/JPEG/GIF/WebP sources with matching signatures and successfully decoded, bounded dimensions, while stripping event handlers and `srcset`. External image URLs and SVG image tags are excluded. The trusted, hash-approved Pico stylesheet can also use its bundled data-URL icons.

Browser decoding is required to check intrinsic dimensions, so byte and pixel caps are mitigations rather than a guarantee against image-decoder resource exhaustion or browser bugs. Displayed image content itself can still be misleading. No network image source is allowed by the iframe CSP.
