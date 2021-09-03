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
const pkcs8 = require('../lib/encoding/pkcs8');

const DSA_PUB_PATH = Path.resolve(__dirname, 'data', 'testdsapub.pem');

const dsaPubPem = fs.readFileSync(DSA_PUB_PATH, 'utf8');

function readPEM(name) {
  const path = Path.resolve(__dirname, 'data', `${name}.pem`);
  return fs.readFileSync(path, 'utf8');
}

// eslint-disable-next-line
const keys = [
  ['DSA', dsa, readPEM('dsa-pkcs8')],
  ['RSA', rsa, readPEM('rsa-pkcs8')],
  ['P256', p256, readPEM('p256-pkcs8')],
  ['SECP256K1', secp256k1, readPEM('secp256k1-pkcs8')],
  ['ED25519', ed25519, readPEM('ed25519-pkcs8')]
];

describe('PKCS8', function() {
  it('should parse PKCS8', () => {
    const pki = pkcs8.PublicKeyInfo.fromPEM(dsaPubPem);

    assert.strictEqual(pki.algorithm.algorithm.getKeyAlgorithmName(), 'DSA');
    assert.strictEqual(pki.algorithm.parameters.node.type, 16); // SEQ
    assert.strictEqual(pki.publicKey.type, 3); // BITSTRING
    assert.strictEqual(pki.publicKey.bits, 1056);

    const br = bio.read(pki.algorithm.parameters.node.value);
    const p = asn1.Unsigned.read(br);
    const q = asn1.Unsigned.read(br);
    const g = asn1.Unsigned.read(br);
    const y = asn1.Unsigned.decode(pki.publicKey.rightAlign());

    const key = dsa.publicKeyImport({
      p: p.value,
      q: q.value,
      g: g.value,
      y: y.value
    });

    assert(dsa.publicKeyVerify(key));

    assert.strictEqual(pki.toPEM(), dsaPubPem.replace(/\r\n/g, '\n'));
  });

  // eslint-disable-next-line
  for (const [name, alg, str1] of keys)
    it(`should parse and reserialize ${name} key`);
});
