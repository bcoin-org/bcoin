/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */
/* eslint no-unused-vars: "off" */

'use strict';

const assert = require('bsert');
const fs = require('fs');
const Path = require('path');
const bio = require('bufio');
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
    const key = new dsa.DSAPublicKey();

    key.setP(p.value);
    key.setQ(q.value);
    key.setG(g.value);
    key.setY(y.value);

    assert(dsa.publicKeyVerify(key));

    assert.strictEqual(spki.toPEM(), dsaPubPem);
  });

  for (const [name, alg, str1] of keys) {
    it(`should parse and reserialize ${name} key`, () => {
      const raw1 = pem.fromPEM(str1, 'PUBLIC KEY');
      const key1 = alg.publicKeyImportSPKI(raw1);
      const raw2 = alg.publicKeyExportSPKI(key1);
      const str2 = pem.toPEM(raw2, 'PUBLIC KEY');
      const raw3 = pem.fromPEM(str2, 'PUBLIC KEY');
      const key2 = alg.publicKeyImportSPKI(raw3);

      assert(alg.publicKeyVerify(key1));
      assert.deepStrictEqual(key1, key2);
    });
  }
});
