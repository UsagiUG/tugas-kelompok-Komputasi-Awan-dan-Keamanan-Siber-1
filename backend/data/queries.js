// data/queries.js
import database from './model.js';

const insertKey = database.prepare(`
  INSERT INTO keys (key_id, public_key, private_key, created_at)
  VALUES (?, ?, ?, ?)
`);

const insertNonce = database.prepare(`
  INSERT INTO nonces (sensor_id, nonce)
  VALUES (?, ?)
`);

const getNonce = database.prepare(`
  SELECT 1 FROM nonces WHERE sensor_id = (?) AND nonce = (?) LIMIT 1
  `);

const insertSessionKey = database.prepare(`
  INSERT INTO session_keys (sensor_id, session_key, created_at)
  VALUES (?, ?, ?)
  `);

const getSessionKey = database.prepare(`
  SELECT session_key FROM session_keys WHERE sensor_id = (?) ORDER BY created_at DESC LIMIT 1
  `);

const getPairByPublic = database.prepare(`
  SELECT * FROM keys WHERE public_key = (?)
`);

const getPairByPrivate = database.prepare(`
  SELECT * FROM keys WHERE private_key = (?)
`);

const insertReading = database.prepare(`
  INSERT INTO readings (sensor_id, mode, received_at, data)
  VALUES (?, ?, ?, ?)
`);

// newest first; sensor_id NULL = all sensors
const getReadings = database.prepare(`
  SELECT id, sensor_id, mode, received_at, data FROM readings
  WHERE (?1 IS NULL OR sensor_id = ?1)
  ORDER BY id DESC
  LIMIT ?2
`);

const getLatestKey = database.prepare(`
  SELECT * FROM keys ORDER BY created_at DESC LIMIT 1
`);

export {
  insertKey,
  getPairByPrivate,
  getPairByPublic,
  getLatestKey,
  insertNonce,
  insertSessionKey,
  getNonce,
  getSessionKey,
  insertReading,
  getReadings
};