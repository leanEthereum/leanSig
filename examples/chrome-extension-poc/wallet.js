import init, {
  DemoKeypair,
  demo_lifetime,
  demo_message_length,
  demo_scheme_name,
  verify_demo_signature,
} from "./pkg/leansig_wasm.js";

const STORAGE_KEY_PREFIX = "leansig-extension-secret-key";
const DEFAULT_MESSAGE_HEX =
  "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const selfTestEnabled = new URLSearchParams(location.search).get("self-test") === "1";

const els = {
  moduleStatus: document.getElementById("module-status"),
  messageLength: document.getElementById("message-length"),
  lifetime: document.getElementById("lifetime"),
  runtimeContext: document.getElementById("runtime-context"),
  storageBackend: document.getElementById("storage-backend"),
  storageStatus: document.getElementById("storage-status"),
  activationInterval: document.getElementById("activation-interval"),
  preparedInterval: document.getElementById("prepared-interval"),
  secretKeyHex: document.getElementById("secret-key-hex"),
  publicKeyHex: document.getElementById("public-key-hex"),
  epochInput: document.getElementById("epoch-input"),
  messageHex: document.getElementById("message-hex"),
  signatureHex: document.getElementById("signature-hex"),
  logOutput: document.getElementById("log-output"),
  generateKey: document.getElementById("generate-key"),
  loadKey: document.getElementById("load-key"),
  importKey: document.getElementById("import-key"),
  exportKey: document.getElementById("export-key"),
  signMessage: document.getElementById("sign-message"),
  verifyMessage: document.getElementById("verify-message"),
  advancePreparation: document.getElementById("advance-preparation"),
  runPerfSample: document.getElementById("run-perf-sample"),
  perfOutput: document.getElementById("perf-output"),
  selfTestPanel: document.getElementById("self-test-panel"),
  selfTestStatus: document.getElementById("self-test-status"),
  selfTestOutput: document.getElementById("self-test-output"),
};

let moduleReady = false;
let keypair = null;

function log(message) {
  const timestamp = new Date().toLocaleTimeString();
  els.logOutput.textContent = `[${timestamp}] ${message}\n${els.logOutput.textContent}`.trim();
}

function bytesToHex(bytes) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function hexToBytes(hex) {
  const normalized = hex.trim().replace(/\s+/g, "").toLowerCase();
  if (normalized.length === 0) {
    return new Uint8Array();
  }
  if (normalized.length % 2 !== 0) {
    throw new Error("hex input must have an even number of characters");
  }

  const bytes = new Uint8Array(normalized.length / 2);
  for (let index = 0; index < normalized.length; index += 2) {
    const value = Number.parseInt(normalized.slice(index, index + 2), 16);
    if (Number.isNaN(value)) {
      throw new Error(`invalid hex at position ${index}`);
    }
    bytes[index / 2] = value;
  }
  return bytes;
}

function formatDuration(milliseconds) {
  if (milliseconds < 1) {
    return `${(milliseconds * 1000).toFixed(2)} µs`;
  }
  if (milliseconds < 1000) {
    return `${milliseconds.toFixed(2)} ms`;
  }
  return `${(milliseconds / 1000).toFixed(2)} s`;
}

function summarizeSamples(label, samples) {
  const sorted = [...samples].sort((left, right) => left - right);
  const total = sorted.reduce((sum, sample) => sum + sample, 0);
  const mean = total / sorted.length;
  const median = sorted[Math.floor(sorted.length / 2)];
  return `${label}: mean ${formatDuration(mean)}, median ${formatDuration(
    median,
  )}, min ${formatDuration(sorted[0])}, max ${formatDuration(sorted[sorted.length - 1])}`;
}

function measureSync(operation) {
  const start = performance.now();
  const result = operation();
  return { duration: performance.now() - start, result };
}

async function yieldToUi() {
  await new Promise((resolve) => setTimeout(resolve, 0));
}

async function getStoredSecretKey() {
  const key = storageKey();
  const values = await chrome.storage.local.get(key);
  return values[key] ?? null;
}

function storageKey() {
  if (!moduleReady) {
    return `${STORAGE_KEY_PREFIX}-pending`;
  }

  return `${STORAGE_KEY_PREFIX}-lifetime-${demo_lifetime()}`;
}

function setSelfTestResult(status, details) {
  document.body.dataset.selfTestStatus = status;
  if (!els.selfTestPanel || !els.selfTestStatus || !els.selfTestOutput) {
    return;
  }

  els.selfTestPanel.hidden = false;
  els.selfTestStatus.textContent = status;
  els.selfTestOutput.textContent = JSON.stringify(details, null, 2);
  window.__leansigSelfTestResult = { status, ...details };
}

async function setStoredSecretKey(secretKeyHex) {
  await chrome.storage.local.set({ [storageKey()]: secretKeyHex });
}

async function updateStorageStatus() {
  const stored = await getStoredSecretKey();
  els.storageStatus.textContent = stored ? "Present" : "Empty";
}

async function persistSecretKey() {
  if (!keypair) {
    return;
  }

  await setStoredSecretKey(bytesToHex(keypair.secretKeyBytes()));
  await updateStorageStatus();
}

function syncKeyFields() {
  if (!keypair) {
    els.activationInterval.textContent = "-";
    els.preparedInterval.textContent = "-";
    els.publicKeyHex.value = "";
    els.secretKeyHex.value = "";
    return;
  }

  const activationStart = keypair.activationIntervalStart();
  const activationEnd = keypair.activationIntervalEnd();
  const preparedStart = keypair.preparedIntervalStart();
  const preparedEnd = keypair.preparedIntervalEnd();

  els.activationInterval.textContent = `[${activationStart}, ${activationEnd})`;
  els.preparedInterval.textContent = `[${preparedStart}, ${preparedEnd})`;
  els.publicKeyHex.value = bytesToHex(keypair.publicKeyBytes());
  els.secretKeyHex.value = bytesToHex(keypair.secretKeyBytes());

  if (!els.epochInput.value) {
    els.epochInput.value = String(preparedStart);
  }
}

function requireReady() {
  if (!moduleReady) {
    throw new Error("WASM module is not ready yet");
  }
}

function requireKeypair() {
  requireReady();
  if (!keypair) {
    throw new Error("No keypair loaded");
  }
}

function readEpoch() {
  const epoch = Number.parseInt(els.epochInput.value, 10);
  if (!Number.isFinite(epoch) || epoch < 0) {
    throw new Error("epoch must be a non-negative integer");
  }
  return epoch;
}

function readMessageBytes() {
  const messageBytes = hexToBytes(els.messageHex.value);
  const expectedLength = Number(demo_message_length());
  if (messageBytes.length !== expectedLength) {
    throw new Error(`message must be exactly ${expectedLength} bytes`);
  }
  return messageBytes;
}

function perfSamplePlan() {
  if (demo_lifetime() >= 1 << 18) {
    return {
      advanceSamples: 1,
      keygenSamples: 1,
      signSamples: 3,
    };
  }

  return {
    advanceSamples: 10,
    keygenSamples: 5,
    signSamples: 24,
  };
}

async function runSelfTest() {
  setSelfTestResult("running", {
    runtimeContext: els.runtimeContext.textContent,
    storageBackend: els.storageBackend.textContent,
  });

  try {
    requireReady();

    const messageBytes = hexToBytes(DEFAULT_MESSAGE_HEX);
    const testKeypair = DemoKeypair.generate();
    const epoch = testKeypair.preparedIntervalStart();
    const signatureBytes = testKeypair.sign(epoch, messageBytes);
    const localVerify = testKeypair.verify(epoch, messageBytes, signatureBytes);
    const detachedVerify = verify_demo_signature(
      testKeypair.publicKeyBytes(),
      epoch,
      messageBytes,
      signatureBytes,
    );

    if (!localVerify || !detachedVerify) {
      throw new Error(
        `self-test verification failed: local=${localVerify}, detached=${detachedVerify}`,
      );
    }

    const preparedBefore = testKeypair.preparedIntervalStart();
    testKeypair.advancePreparation();
    const preparedAfter = testKeypair.preparedIntervalStart();

    setSelfTestResult("passed", {
      moduleStatus: els.moduleStatus.textContent,
      runtimeContext: els.runtimeContext.textContent,
      storageBackend: els.storageBackend.textContent,
      messageLength: demo_message_length(),
      lifetime: demo_lifetime(),
      epoch,
      publicKeyLength: testKeypair.publicKeyBytes().length,
      signatureLength: signatureBytes.length,
      preparedBefore,
      preparedAfter,
      localVerify,
      detachedVerify,
    });
    log("Self-test passed.");
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    setSelfTestResult("failed", {
      moduleStatus: els.moduleStatus.textContent,
      runtimeContext: els.runtimeContext.textContent,
      storageBackend: els.storageBackend.textContent,
      error: message,
    });
    log(`Self-test failed: ${message}`);
  }
}

function installHandlers() {
  els.generateKey.addEventListener("click", async () => {
    try {
      requireReady();
      keypair = DemoKeypair.generate();
      await persistSecretKey();
      syncKeyFields();
      els.signatureHex.value = "";
      log("Generated a fresh demo keypair.");
    } catch (error) {
      log(`Generate failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  });

  els.loadKey.addEventListener("click", async () => {
    try {
      requireReady();
      const stored = await getStoredSecretKey();
      if (!stored) {
        throw new Error("no stored secret key");
      }
      keypair = new DemoKeypair(hexToBytes(stored));
      syncKeyFields();
      log("Loaded keypair from chrome.storage.local.");
    } catch (error) {
      log(`Load failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  });

  els.importKey.addEventListener("click", async () => {
    try {
      requireReady();
      keypair = new DemoKeypair(hexToBytes(els.secretKeyHex.value));
      await persistSecretKey();
      syncKeyFields();
      log("Imported secret key bytes.");
    } catch (error) {
      log(`Import failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  });

  els.exportKey.addEventListener("click", () => {
    try {
      requireKeypair();
      syncKeyFields();
      log("Refreshed exported public and secret key bytes.");
    } catch (error) {
      log(`Export failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  });

  els.signMessage.addEventListener("click", async () => {
    try {
      requireKeypair();
      const epoch = readEpoch();
      const messageBytes = readMessageBytes();
      const signatureBytes = keypair.sign(epoch, messageBytes);
      els.signatureHex.value = bytesToHex(signatureBytes);
      await persistSecretKey();
      syncKeyFields();
      log(`Signed message for epoch ${epoch}.`);
    } catch (error) {
      log(`Sign failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  });

  els.verifyMessage.addEventListener("click", () => {
    try {
      requireKeypair();
      const epoch = readEpoch();
      const messageBytes = readMessageBytes();
      const signatureBytes = hexToBytes(els.signatureHex.value);
      const localResult = keypair.verify(epoch, messageBytes, signatureBytes);
      const detachedResult = verify_demo_signature(
        keypair.publicKeyBytes(),
        epoch,
        messageBytes,
        signatureBytes,
      );
      log(
        `Verify result for epoch ${epoch}: local=${localResult}, detached=${detachedResult}.`,
      );
    } catch (error) {
      log(`Verify failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  });

  els.advancePreparation.addEventListener("click", async () => {
    try {
      requireKeypair();
      keypair.advancePreparation();
      await persistSecretKey();
      syncKeyFields();
      log("Advanced the prepared interval.");
    } catch (error) {
      log(`Advance failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  });

  els.runPerfSample.addEventListener("click", async () => {
    try {
      requireReady();
      const messageBytes = readMessageBytes();
      const keygenSamples = [];
      const signSamples = [];
      const verifySamples = [];
      const advanceSamples = [];
      const plan = perfSamplePlan();

      let perfKeypair = null;
      for (let iteration = 0; iteration < plan.keygenSamples; iteration += 1) {
        const sample = measureSync(() => DemoKeypair.generate());
        keygenSamples.push(sample.duration);
        perfKeypair = sample.result;
        await yieldToUi();
      }

      if (!perfKeypair) {
        throw new Error("perf key generation did not produce a keypair");
      }

      const perfPublicKey = perfKeypair.publicKeyBytes();
      let nextEpoch = perfKeypair.preparedIntervalStart();
      const preparedEnd = perfKeypair.preparedIntervalEnd();

      for (
        let iteration = 0;
        iteration < plan.signSamples && nextEpoch < preparedEnd;
        iteration += 1
      ) {
        const signSample = measureSync(() => perfKeypair.sign(nextEpoch, messageBytes));
        signSamples.push(signSample.duration);

        const verifySample = measureSync(() =>
          verify_demo_signature(perfPublicKey, nextEpoch, messageBytes, signSample.result),
        );
        if (!verifySample.result) {
          throw new Error(`detached verification failed for perf sample epoch ${nextEpoch}`);
        }
        verifySamples.push(verifySample.duration);
        nextEpoch += 1;
        await yieldToUi();
      }

      const preparationKey =
        demo_lifetime() >= 1 << 18 ? perfKeypair : DemoKeypair.generate();
      for (let iteration = 0; iteration < plan.advanceSamples; iteration += 1) {
        const before = preparationKey.preparedIntervalStart();
        const sample = measureSync(() => preparationKey.advancePreparation());
        advanceSamples.push(sample.duration);
        if (preparationKey.preparedIntervalStart() === before) {
          break;
        }
        await yieldToUi();
      }

      const lines = [
        `Runtime: Chrome extension (${chrome.runtime.id})`,
        `Scheme: ${demo_scheme_name()}`,
        "Storage: chrome.storage.local",
        summarizeSamples(`keygen (${keygenSamples.length} samples)`, keygenSamples),
        summarizeSamples(`sign (${signSamples.length} samples)`, signSamples),
        summarizeSamples(`verify (${verifySamples.length} samples)`, verifySamples),
        summarizeSamples(
          `advance_preparation (${advanceSamples.length} samples)`,
          advanceSamples,
        ),
      ];

      els.perfOutput.textContent = lines.join("\n");
      log("Collected a local performance sample.");
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      els.perfOutput.textContent = `Perf sample failed: ${message}`;
      log(`Perf sample failed: ${message}`);
    }
  });
}

async function boot() {
  installHandlers();
  els.runtimeContext.textContent = `Chrome extension (${chrome.runtime.id})`;
  els.storageBackend.textContent = "chrome.storage.local";
  if (selfTestEnabled && els.selfTestPanel) {
    els.selfTestPanel.hidden = false;
    setSelfTestResult("armed", {
      runtimeContext: els.runtimeContext.textContent,
      storageBackend: els.storageBackend.textContent,
    });
  }
  if (!els.messageHex.value) {
    els.messageHex.value = DEFAULT_MESSAGE_HEX;
  }
  await updateStorageStatus();

  try {
    await init();
    moduleReady = true;
    els.moduleStatus.textContent = "Ready";
    els.messageLength.textContent = `${demo_message_length()} bytes`;
    els.lifetime.textContent = `${demo_lifetime()} epochs (${demo_scheme_name()})`;
    log("WASM module initialized.");
    await updateStorageStatus();

    const stored = await getStoredSecretKey();
    if (stored) {
      keypair = new DemoKeypair(hexToBytes(stored));
      syncKeyFields();
      log("Recovered stored keypair.");
    }

    if (selfTestEnabled) {
      await runSelfTest();
    }
  } catch (error) {
    els.moduleStatus.textContent = "Failed";
    const message = error instanceof Error ? error.message : String(error);
    if (selfTestEnabled) {
      setSelfTestResult("failed", {
        moduleStatus: els.moduleStatus.textContent,
        runtimeContext: els.runtimeContext.textContent,
        storageBackend: els.storageBackend.textContent,
        error: message,
      });
    }
    log(`Module init failed: ${message}`);
  }
}

boot();
