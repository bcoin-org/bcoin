/* eslint no-unused-vars: "off" */

'use strict';

const assert = require('bsert');
const fs = require('fs');
const Path = require('path');
const bio = require('bufio');
// eslint-disable-next-line
const pem = require('../lib/encoding/pem');
const dsa = require('../lib/dsa');
const rsa = require('../lib/rsa');
const p256 = require('../lib/p256');
const secp256k1 = require('../lib/secp256k1');
const ed25519 = require('../lib/ed25519');
const asn1 = require('../lib/encoding/asn1');
const x509 = require('../lib/encoding/x509');

const DSA_PUB_PATH = Path.resolve(__dirname, 'data', 'testdsapub.pem');

const dsaPubPem = fs.readFileSync(DSA_PUB_PATH, 'utf8');

function readPEM(name) {
  const path = Path.resolve(__dirname, 'data', `${name}.pem`);
  return fs.readFileSync(path, 'utf8');
}

// eslint-disable-next-line
const keys = [
  ['DSA', dsa, readPEM('dsa-spki')],
  ['RSA', rsa, readPEM('rsa-spki')],
  ['P256', p256, readPEM('p256-spki')],
  ['SECP256K1', secp256k1, readPEM('secp256k1-spki')],
  ['ED25519', ed25519, readPEM('ed25519-spki')]
];

describe('SPKI', function() {
  it('should parse SPKI', () => {
    const spki = x509.SubjectPublicKeyInfo.fromPEM(dsaPubPem);

    assert(Buffer.isBuffer(spki.raw));
    assert.strictEqual(spki.raw.length, 444);
    assert.strictEqual(spki.algorithm.algorithm.getKeyAlgorithmName(), 'DSA');
    assert.strictEqual(spki.algorithm.parameters.node.type, 16); // SEQ
    assert.strictEqual(spki.publicKey.type, 3); // BITSTRING
    assert.strictEqual(spki.publicKey.bits, 1056);

    const br = bio.read(spki.algorithm.parameters.node.value);
    const p = asn1.Unsigned.read(br);
    const q = asn1.Unsigned.read(br);
    const g = asn1.Unsigned.read(br);
    const y = asn1.Unsigned.decode(spki.publicKey.rightAlign());

    const key = dsa.publicKeyImport({
      p: p.value,
      q: q.value,
      g: g.value,
      y: y.value
    });

    assert(dsa.publicKeyVerify(key));

    assert.strictEqual(spki.toPEM(), dsaPubPem.replace(/\r\n/g, '\n'));
  });

  // eslint-disable-next-line
  for (const [name, alg, str1] of keys)
    it(`should parse and reserialize ${name} key`);
});
