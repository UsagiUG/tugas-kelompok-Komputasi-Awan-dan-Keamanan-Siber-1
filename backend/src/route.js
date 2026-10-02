import express from 'express';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import RSAUtils from './rsaUtils.js';
import AESUtils from './aesUtils.js';
import ECCUtils from './eccUtils.js';
import { insertNonce, insertReading, getReadings } from '../data/queries.js';

// ---------------------------------------------------------------------------
// Configuration (all overridable with environment variables for the cloud)
// ---------------------------------------------------------------------------
const thisFilePath = path.dirname(fileURLToPath(import.meta.url));
const RSA_KEY_PATH = process.env.RSA_KEY_PATH || path.resolve(thisFilePath, '../certs/rsa_private_key.pem');
const ECC_KEY_PATH = process.env.ECC_KEY_PATH || path.resolve(thisFilePath, '../certs/ecc_private_key.pem');

// Accepted message age: up to MAX_AGE_MS in the past, up to MAX_SKEW_MS in the
// future (sensor clock slightly ahead of the server).
const MAX_AGE_MS = Number(process.env.MAX_AGE_MS ?? 30000);
const MAX_SKEW_MS = Number(process.env.MAX_SKEW_MS ?? 5000);

// Printing decrypted readings is for local debugging only; never on in the cloud.
const DEBUG_PLAINTEXT = process.env.DEBUG_PLAINTEXT === 'true';

// Token that protects GET /readings (sent as "Authorization: Bearer <token>").
// Not set = the endpoint is switched off.
const READINGS_TOKEN = (process.env.READINGS_TOKEN || '').trim();

// ---------------------------------------------------------------------------
// Key loading. A PEM given directly in an environment variable (Azure Key
// Vault reference, Cloud Run secret as env var) wins over the file path.
// Private keys are never logged.
// ---------------------------------------------------------------------------
function loadPrivateKey(label, envPem, filePath) {
  try {
    const pem = envPem || fs.readFileSync(filePath, 'utf-8');
    const privateKey = crypto.createPrivateKey(pem);
    const publicKey = crypto.createPublicKey(privateKey);
    const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' });
    // SHA-256 of the DER public key: public information, printed so clients can
    // compare it with what they received from /public-key.
    const fingerprint = crypto.createHash('sha256')
      .update(publicKey.export({ type: 'spki', format: 'der' })).digest('hex');
    console.log(`${label} private key loaded, public key sha256 ${fingerprint}`);
    return { pem, publicKeyPem, fingerprint };
  } catch (err) {
    console.error(`${label} private key failed to load: ${err.message}`);
    return null;
  }
}

const rsaKey = loadPrivateKey('RSA', process.env.RSA_PRIVATE_KEY_PEM, RSA_KEY_PATH);
const eccKey = loadPrivateKey('ECC', process.env.ECC_PRIVATE_KEY_PEM, ECC_KEY_PATH);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
class HttpError extends Error {
  constructor(status, publicMessage, detail) {
    super(detail || publicMessage);
    this.status = status;
    this.publicMessage = publicMessage;
  }
}

const BASE64_RE = /^[A-Za-z0-9+/]+={0,2}$/;

function isBase64(value, expectedBytes) {
  if (typeof value !== 'string' || value.length === 0 || !BASE64_RE.test(value)) return false;
  if (expectedBytes === undefined) return true;
  return Buffer.from(value, 'base64').length === expectedBytes;
}

// Checks the request shape before anything touches it.
function validateBody(body) {
  if (!body || typeof body !== 'object') throw new HttpError(400, 'invalid request', 'body is not a JSON object');
  const { aad, nonce, ciphertext, tag } = body;
  if (!aad || typeof aad !== 'object' || Array.isArray(aad)) throw new HttpError(400, 'invalid request', 'aad missing');

  const { sensor_id, mode, transmission_timestamp, key } = aad;
  if (!Number.isInteger(sensor_id) || sensor_id < 0) throw new HttpError(400, 'invalid request', 'bad sensor_id');
  if (mode !== 'rsa' && mode !== 'ecc') throw new HttpError(400, 'invalid request', 'bad mode');
  if (typeof transmission_timestamp !== 'string') throw new HttpError(400, 'invalid request', 'bad timestamp');
  if (!isBase64(key)) throw new HttpError(400, 'invalid request', 'bad key');
  if (!isBase64(nonce, 12)) throw new HttpError(400, 'invalid request', 'nonce must be 12 bytes');
  if (!isBase64(ciphertext)) throw new HttpError(400, 'invalid request', 'bad ciphertext');
  if (!isBase64(tag, 16)) throw new HttpError(400, 'invalid request', 'tag must be 16 bytes');

  return { sensor_id, mode, transmission_timestamp, nonce };
}

// Rejects stale, future-dated and unparseable timestamps.
// (Before: an unparseable date gave NaN, and NaN comparisons are always
// false, so such messages were accepted.)
function checkFreshness(transmission_timestamp) {
  const sentTime = Date.parse(transmission_timestamp);
  if (!Number.isFinite(sentTime)) throw new HttpError(400, 'invalid request', 'unparseable timestamp');
  const age = Date.now() - sentTime;
  if (age > MAX_AGE_MS || age < -MAX_SKEW_MS) {
    throw new HttpError(400, 'invalid request', `message outside time window (age ${age} ms)`);
  }
}

// Recovers the AES session key, then decrypts and verifies the GCM tag.
function decryption(body, mode) {
  const { key } = body.aad;
  let sessionKey;
  if (mode === 'rsa') {
    if (!rsaKey) throw new HttpError(500, 'internal server error', 'RSA key not loaded');
    try {
      sessionKey = RSAUtils.decrypt(rsaKey.pem, key);
    } catch (err) {
      throw new HttpError(400, 'invalid request', `RSA unwrap failed: ${err.message}`);
    }
  } else {
    if (!eccKey) throw new HttpError(500, 'internal server error', 'ECC key not loaded');
    try {
      sessionKey = ECCUtils.decrypt(eccKey.pem, key);
    } catch (err) {
      throw new HttpError(400, 'invalid request', `ECC key agreement failed: ${err.message}`);
    }
  }

  try {
    return AESUtils.decrypt(sessionKey, body);
  } catch (err) {
    throw new HttpError(400, 'invalid request', `AES-GCM decrypt or tag check failed: ${err.message}`);
  }
}

// Records (sensor_id, nonce). The UNIQUE constraint makes check-and-insert a
// single atomic step. Called only after the GCM tag verified, so unauthenticated
// junk cannot fill the table.
function claimNonce(sensor_id, nonce) {
  try {
    insertNonce.run(sensor_id, nonce);
  } catch (err) {
    if (String(err.message).includes('UNIQUE')) throw new HttpError(409, 'replayed message', 'duplicate sensor_id + nonce');
    throw new HttpError(500, 'internal server error', `nonce insert failed: ${err.message}`);
  }
}

// Saves the decrypted reading. The benchmark's "dummy" padding (up to 100 KB)
// is dropped so only the sensor values are kept.
function storeReading(sensor_id, mode, decryptedMessage) {
  let data = decryptedMessage;
  try {
    const parsed = JSON.parse(decryptedMessage);
    if (parsed && typeof parsed === 'object') {
      delete parsed.dummy;
      data = JSON.stringify(parsed);
    }
  } catch { /* not JSON: store as received */ }
  try {
    insertReading.run(sensor_id, mode, new Date().toISOString(), data);
  } catch (err) {
    // the message was valid; a storage problem must not turn it into an error
    console.error(JSON.stringify({ event: 'reading_store_failed', sensor_id, reason: err.message }));
  }
}

function tokenMatches(header) {
  if (!READINGS_TOKEN || typeof header !== 'string' || !header.startsWith('Bearer ')) return false;
  const given = crypto.createHash('sha256').update(header.slice(7)).digest();
  const expected = crypto.createHash('sha256').update(READINGS_TOKEN).digest();
  return crypto.timingSafeEqual(given, expected);
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------
const router = express.Router();

// Public keys the sensors encrypt to, derived from the loaded private keys.
router.get('/public-key', (req, res) => {
  if (!rsaKey && !eccKey) return res.status(500).json({ error: 'internal server error' });
  res.json({
    rsa_public_key: rsaKey?.publicKeyPem ?? null,
    ecc_public_key: eccKey?.publicKeyPem ?? null,
    rsa_fingerprint_sha256: rsaKey?.fingerprint ?? null,
    ecc_fingerprint_sha256: eccKey?.fingerprint ?? null
  });
});

router.post('/telemetry', (req, res) => {
  const start = performance.now();
  let meta = {};
  try {
    meta = validateBody(req.body);
    checkFreshness(meta.transmission_timestamp);
    const decryptedMessage = decryption(req.body, meta.mode);
    const end = performance.now();
    claimNonce(meta.sensor_id, meta.nonce);
    storeReading(meta.sensor_id, meta.mode, decryptedMessage);

    console.log(JSON.stringify({
      event: 'telemetry_ok', sensor_id: meta.sensor_id, mode: meta.mode,
      decrypt_ms: +(end - start).toFixed(3), time: new Date().toISOString()
    }));
    if (DEBUG_PLAINTEXT) console.log({ decryptedMessage });

    // decryption_duration is in milliseconds (performance.now() units).
    res.json({ decryption_duration: end - start });
  } catch (err) {
    const status = err instanceof HttpError ? err.status : 500;
    console.error(JSON.stringify({
      event: 'telemetry_rejected', status, sensor_id: meta.sensor_id, mode: meta.mode,
      reason: err.message, time: new Date().toISOString()
    }));
    res.status(status).json({ error: err instanceof HttpError ? err.publicMessage : 'internal server error' });
  }
});

// Removed: /generate-keys, /encrypt and /decrypt. They were unauthenticated
// test endpoints; /decrypt returned plaintext for any stored key.

// Decrypted readings, newest first. Protected by READINGS_TOKEN.
//   GET /readings?sensor_id=1&limit=20
router.get('/readings', (req, res) => {
  if (!READINGS_TOKEN) return res.status(404).json({ error: 'not found' });
  if (!tokenMatches(req.get('authorization'))) {
    console.error(JSON.stringify({ event: 'readings_unauthorized', time: new Date().toISOString() }));
    return res.status(401).json({ error: 'unauthorized' });
  }
  const sensorId = req.query.sensor_id === undefined ? null : Number(req.query.sensor_id);
  if (sensorId !== null && !Number.isInteger(sensorId)) return res.status(400).json({ error: 'invalid request' });
  const limit = Math.min(Math.max(parseInt(req.query.limit ?? '20', 10) || 20, 1), 500);

  const rows = getReadings.all(sensorId, limit).map(r => {
    let data;
    try { data = JSON.parse(r.data); } catch { data = r.data; }
    return { id: r.id, sensor_id: r.sensor_id, mode: r.mode, received_at: r.received_at, data };
  });
  res.json({ count: rows.length, readings: rows });
});

export default router;
