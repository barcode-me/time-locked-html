'use strict';

const { timelockDecrypt, defaultChainInfo, defaultChainUrl, roundTime, Buffer } = require('tlock-js');

// Pin quicknet's public key and schedule; no untrusted chain-info requests.
function roundForTimestamp(timestamp) {
  if (!Number.isSafeInteger(timestamp) || timestamp < defaultChainInfo.genesis_time * 1000 || Number.isNaN(new Date(timestamp).getTime())) {
    throw Error('Drand timestamp must be Unix milliseconds on or after quicknet genesis.');
  }
  return Math.ceil((timestamp - defaultChainInfo.genesis_time * 1000) / (defaultChainInfo.period * 1000)) + 1;
}

function client(signal) {
  return {
    options: { disableBeaconVerification: false },
    chain: () => ({ info: async () => defaultChainInfo }),
    async get(round) {
      const controller = new AbortController();
      const abort = () => controller.abort();
      signal?.addEventListener('abort', abort, { once: true });
      if (signal?.aborted) controller.abort();
      const timer = setTimeout(abort, 10000);
      try {
        const response = await fetch(defaultChainUrl + '/public/' + round, {
          signal: controller.signal, credentials: 'omit', redirect: 'error'
        });
        if (!response.ok) throw Error('Drand beacon is unavailable.');
        return await response.json();
      } finally { clearTimeout(timer); signal?.removeEventListener('abort', abort); }
    }
  };
}

function validateTarget(target) {
  if (!target || target.chainHash !== defaultChainInfo.hash || target.round !== roundForTimestamp(target.timestamp) ||
      typeof target.encryptedPassword !== 'string' || target.encryptedPassword.length > 65536 ||
      !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(target.encryptedPassword) || !target.encryptedPassword) {
    throw Error('Invalid drand target.');
  }
  return roundTime(defaultChainInfo, target.round);
}

async function decryptPassword(target, signal) {
  const due = validateTarget(target);
  if (Date.now() < due) throw Error('Drand round is in the future.');
  const armor = Buffer.from(target.encryptedPassword, 'base64').toString('utf8');
  const result = await timelockDecrypt(armor, client(signal));
  return new TextDecoder('utf-8', { fatal: true }).decode(result);
}

module.exports = { client, roundForTimestamp, validateTarget, decryptPassword };
