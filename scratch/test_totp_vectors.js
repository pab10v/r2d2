// RFC 6238 regression tests for SecureTOTP.
// Run: node scratch/test_totp_vectors.js

const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { webcrypto } = require('node:crypto');

globalThis.crypto = webcrypto;
globalThis.self = globalThis;

const totpSource = fs.readFileSync(path.join(__dirname, '..', 'totp.js'), 'utf8');
vm.runInThisContext(totpSource, { filename: 'totp.js' });

async function run() {
  const totp = new SecureTOTP(false);

  const vectors = [
    { time: 59, sha1: '94287082', sha256: '46119246', sha512: '90693936' },
    { time: 1111111109, sha1: '07081804', sha256: '68084774', sha512: '25091201' },
    { time: 1111111111, sha1: '14050471', sha256: '67062674', sha512: '99943326' },
    { time: 1234567890, sha1: '89005924', sha256: '91819424', sha512: '93441116' },
    { time: 2000000000, sha1: '69279037', sha256: '90698825', sha512: '38618901' },
    { time: 20000000000, sha1: '65353130', sha256: '77737706', sha512: '47863826' }
  ];

  const secrets = {
    SHA1: asciiToBase32('12345678901234567890'),
    SHA256: asciiToBase32('12345678901234567890123456789012'),
    SHA512: asciiToBase32('1234567890123456789012345678901234567890123456789012345678901234')
  };

  let failures = 0;
  for (const vector of vectors) {
    const tsMs = vector.time * 1000;
    const gotSha1 = await totp.generate(secrets.SHA1, 30, 8, 'SHA1', tsMs);
    const gotSha256 = await totp.generate(secrets.SHA256, 30, 8, 'SHA256', tsMs);
    const gotSha512 = await totp.generate(secrets.SHA512, 30, 8, 'SHA512', tsMs);

    const checks = [
      ['SHA1', gotSha1, vector.sha1],
      ['SHA256', gotSha256, vector.sha256],
      ['SHA512', gotSha512, vector.sha512]
    ];

    for (const [algo, actual, expected] of checks) {
      if (actual !== expected) {
        failures += 1;
        console.error(`FAIL ${algo} @ t=${vector.time}: expected=${expected}, got=${actual}`);
      }
    }
  }

  if (failures > 0) {
    console.error(`\n${failures} vector checks failed.`);
    process.exitCode = 1;
    return;
  }

  console.log('All RFC 6238 vectors passed (SHA1/SHA256/SHA512).');
}

function asciiToBase32(input) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const bytes = Buffer.from(input, 'ascii');
  let bits = '';
  for (const b of bytes) {
    bits += b.toString(2).padStart(8, '0');
  }

  let out = '';
  for (let i = 0; i < bits.length; i += 5) {
    const chunk = bits.slice(i, i + 5).padEnd(5, '0');
    out += alphabet[parseInt(chunk, 2)];
  }
  return out;
}

run().catch((err) => {
  console.error('Unexpected test error:', err);
  process.exitCode = 1;
});
