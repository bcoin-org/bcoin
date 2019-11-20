/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */
/* eslint no-unused-vars: "off" */

'use strict';

const assert = require('bsert');
const fs = require('fs');
const Path = require('path');
const bio = require('bufio');
const dsa = require('../lib/dsa');
const random = require('../lib/random');
const asn1 = require('../lib/encoding/asn1');
const x509 = require('../lib/encoding/x509');
const params = require('./data/dsa-params.json');
const vectors = require('./data/dsa.json');

const {
  DSAParams,
  DSAPublicKey,
  DSAPrivateKey
} = dsa;

const DSA_PATH = Path.resolve(__dirname, 'data', 'testdsa.pem');
const DSA_PUB_PATH = Path.resolve(__dirname, 'data', 'testdsapub.pem');

const dsaPem = fs.readFileSync(DSA_PATH, 'utf8');
const dsaPubPem = fs.readFileSync(DSA_PUB_PATH, 'utf8');

const {
  P1024_160,
  P2048_244,
  P2048_256,
  P3072_256
} = params;

function createParams(json) {
  const p = Buffer.from(json.p, 'hex');
  const q = Buffer.from(json.q, 'hex');
  const g = Buffer.from(json.g, 'hex');
  return new dsa.DSAParams(p, q, g);
}

describe('DSA', function() {
  this.timeout(30000);

  it('should sign and verify', () => {
    // const priv = dsa.privateKeyGenerate(1024);
    const params = createParams(P2048_256);
    const priv = dsa.privateKeyCreate(params);
    const pub = dsa.publicKeyCreate(priv);

    assert(dsa.privateKeyVerify(priv));
    assert(dsa.publicKeyVerify(pub));

    const msg = Buffer.alloc(priv.size(), 0x01);
    const sig = dsa.sign(msg, priv);
    assert(sig);

    const result = dsa.verify(msg, sig, pub);
    assert(result);

    const zero = Buffer.alloc(0);
    assert(!dsa.verify(zero, sig, pub));
    assert(!dsa.verify(msg, zero, pub));

    sig[(Math.random() * sig.length) | 0] ^= 1;

    const result2 = dsa.verify(msg, sig, pub);
    assert(!result2);

    assert.deepStrictEqual(
      dsa.privateKeyImport(dsa.privateKeyExport(priv)),
      priv);

    assert.deepStrictEqual(
      dsa.privateKeyImportPKCS8(dsa.privateKeyExportPKCS8(priv)),
      priv);

    assert.deepStrictEqual(
      dsa.privateKeyImportJWK(dsa.privateKeyExportJWK(priv)),
      priv);

    assert.deepStrictEqual(
      dsa.publicKeyImport(dsa.publicKeyExport(pub)),
      pub);

    assert.deepStrictEqual(
      dsa.publicKeyImportSPKI(dsa.publicKeyExportSPKI(pub)),
      pub);

    assert.deepStrictEqual(
      dsa.publicKeyImportJWK(dsa.publicKeyExportJWK(pub)),
      pub);
  });

  it('should sign and verify (async)', async () => {
    const size = dsa.native < 2 ? 1024 : 2048;
    const params = await dsa.paramsGenerateAsync(size);
    const priv = dsa.privateKeyCreate(params);
    const pub = dsa.publicKeyCreate(priv);

    assert(dsa.privateKeyVerify(priv));
    assert(dsa.publicKeyVerify(pub));

    const msg = Buffer.alloc(priv.size(), 0x01);
    const sig = dsa.sign(msg, priv);
    assert(sig);

    const result = dsa.verify(msg, sig, pub);
    assert(result);

    sig[(Math.random() * sig.length) | 0] ^= 1;

    const result2 = dsa.verify(msg, sig, pub);
    assert(!result2);
  });

  it('should do diffie hellman', () => {
    // const params = createParams(P2048_256);
    const params = dsa.paramsGenerate(1024);
    const alice = dsa.privateKeyCreate(params);
    const alicePub = dsa.publicKeyCreate(alice);
    const bob = dsa.privateKeyCreate(params);
    const bobPub = dsa.publicKeyCreate(bob);

    const aliceSecret = dsa.derive(bobPub, alice);
    const bobSecret = dsa.derive(alicePub, bob);

    assert.bufferEqual(aliceSecret, bobSecret);
  });

  it('should parse SPKI', () => {
    const info = x509.SubjectPublicKeyInfo.fromPEM(dsaPubPem);
    assert(info.algorithm.algorithm.getKeyAlgorithmName() === 'DSA');
    assert(info.algorithm.parameters.node.type === 16); // SEQ
    assert(info.publicKey.type === 3); // BITSTRING

    const br = bio.read(info.algorithm.parameters.node.value);
    const p = asn1.Unsigned.read(br);
    const q = asn1.Unsigned.read(br);
    const g = asn1.Unsigned.read(br);
    const y = asn1.Unsigned.decode(info.publicKey.rightAlign());
    const key = new DSAPublicKey();

    key.setP(p.value);
    key.setQ(q.value);
    key.setG(g.value);
    key.setY(y.value);

    assert(dsa.publicKeyVerify(key));
  });

  for (const vector of vectors) {
    it(`should verify signature: ${vector.sig}`, () => {
      const msg = Buffer.from(vector.msg, 'hex');
      const sig = Buffer.from(vector.sig, 'hex');
      const pubRaw = Buffer.from(vector.pub, 'hex');
      const privRaw = Buffer.from(vector.priv, 'hex');
      const priv = dsa.privateKeyImport(privRaw);
      const pub = dsa.publicKeyCreate(priv);

      assert.bufferEqual(dsa.publicKeyExport(pub), pubRaw);

      const result = dsa.verify(msg, sig, pub);
      assert.strictEqual(result, true);

      sig[(Math.random() * sig.length) | 0] ^= 1;

      const result2 = dsa.verify(msg, sig, pub);
      assert.strictEqual(result2, false);
    });
  }

  it('should sign zero-length message', () => {
    const msg = Buffer.alloc(0);
    const key = dsa.privateKeyGenerate(1024);
    const pub = dsa.publicKeyCreate(key);
    const sig = dsa.sign(msg, key);
    assert(dsa.verify(msg, sig, pub));
  });
});
