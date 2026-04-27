# LeanSig Chrome Extension PoC

This is a minimal MV3 Chrome extension proof of concept around `crates/leansig-wasm`.
It packages LeanXMSS-style signing into an extension page and loads the crypto through
`wasm-bindgen`-generated WASM assets.

By default it keeps the same small demo scheme as the browser harness:
- Lifetime: `2^10`
- Encoding: target sum
- Chunk size: `w = 2`

It can also be built against a larger benchmark-oriented scheme:
- Lifetime: `2^18`
- Encoding: target sum
- Chunk size: `w = 2`

## Build

From the repo root:

```bash
./examples/chrome-extension-poc/build.sh
```

This will:
1. build `leansig-wasm` for `wasm32-unknown-unknown`
2. run `wasm-bindgen --target web`
3. emit the packaged extension assets into `examples/chrome-extension-poc/pkg/`

To build the same extension UI against the larger benchmark-oriented `2^18 / w=2`
scheme, run:

```bash
./examples/chrome-extension-poc/build.sh production
```

The production build intentionally uses fewer in-page performance samples because
key generation can take minutes in single-threaded WASM.

Re-run the build command whenever you switch between demo and production mode, then reload
the unpacked extension in Chrome.

## Load In Chrome

1. Open `chrome://extensions`
2. Enable Developer mode
3. Click `Load unpacked`
4. Select `examples/chrome-extension-poc/`
5. Click the extension action to open the wallet page in a new tab

After the page opens:

1. Click `Generate Demo Key`.
2. Check that the runtime panel says `Module: Ready`.
3. Click `Sign`.
4. Click `Verify`.
5. Check the log for `local=true, detached=true`.
6. Click `Run Perf Sample` to measure the active build inside the Chrome extension runtime.

For the production build, the perf sample intentionally runs only one key-generation sample.
Expect the page to be busy while that sample runs.

## What The PoC Covers

- generate a demo keypair inside an MV3 extension page
- persist the secret key in `chrome.storage.local`
- export and import secret key bytes
- inspect activation and prepared intervals
- sign a 32-byte message for a chosen epoch
- verify through both the keypair instance and the detached public-key API
- advance the prepared interval manually
- run an extension-side performance sample using `performance.now()`

`local=true` means the signature verified through the loaded keypair object.
`detached=true` means verification succeeded using only public key bytes, epoch, message bytes,
and signature bytes. The detached path is the closest browser-side analogue to a wallet producing
a signature and another component verifying it without access to the secret key.

The verifier here is a WASM/JS-side detached verifier, not an on-chain verifier.

## Self-Test

For automated validation, open:

```text
chrome-extension://<extension-id>/wallet.html?self-test=1
```

This runs an in-page smoke test after WASM initialization:

- generate a temporary keypair
- sign and verify the default 32-byte message
- advance preparation once
- publish the result into the DOM via `data-self-test-status` on `<body>` and the
  `#self-test-output` JSON block

## Important Limitation

This is a stateful signature scheme demo, not a production wallet flow.
Reusing epochs or mishandling secret-key state can break the security model.
