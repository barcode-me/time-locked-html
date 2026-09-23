'use strict';

const { randomBytes, pbkdf2, createCipheriv } = require('node:crypto');
const { promisify } = require('node:util');
const derive = promisify(pbkdf2);

async function encrypt(html, password) {
  const salt = randomBytes(16), iv = randomBytes(12);
  const key = await derive(password, salt, 600000, 32, 'sha256');
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const data = Buffer.concat([cipher.update(html, 'utf8'), cipher.final(), cipher.getAuthTag()]);
  key.fill(0);
  return { salt: salt.toString('base64'), iv: iv.toString('base64'), data: data.toString('base64') };
}

async function encryptDrandPassword(password, timestamp) {
  const { timelockEncrypt, defaultChainInfo, Buffer: TlockBuffer } = require('tlock-js');
  const { client, roundForTimestamp } = require('./drand.cjs');
  const round = roundForTimestamp(timestamp);
  if (timestamp <= Date.now()) throw Error('Drand encryption requires a future timestamp.');
  const ciphertext = await timelockEncrypt(round, TlockBuffer.from(password, 'utf8'), client());
  return { timestamp, round, chainHash: defaultChainInfo.hash, encryptedPassword: Buffer.from(ciphertext, 'utf8').toString('base64') };
}

module.exports = { encrypt, encryptDrandPassword };
