'use strict';

const assert = require('bsert');
const fs = require('fs');
const Path = require('path');
const bio = require('bufio');
const dsa = require('../lib/dsa');
const asn1 = require('../lib/encoding/asn1');
const x509 = require('../lib/encoding/x509');
const params = require('./data/dsa-params.json');
const vectors = require('./data/dsa.json');
const custom = require('./data/sign/dsa.json');

const FAST = dsa.native === 2 && process.platform !== 'win32';
const PEM_PATH = Path.resolve(__dirname, 'data', 'testdsapub.pem');
const PEM_TXT = fs.readFileSync(PEM_PATH, 'utf8');

const {
  P1024_160,
  P2048_256
  // P3072_256
} = params;

function createParams(json) {
  const p = Buffer.from(json.p, 'hex');
  const q = Buffer.from(json.q, 'hex');
  const g = Buffer.from(json.g, 'hex');

  return dsa.paramsImport({ p, q, g });
}

describe('DSA', function() {
  this.timeout(120000);

  it('should sign and verify', () => {
    const params = createParams(P2048_256);
    const priv = dsa.privateKeyCreate(params);
    const pub = dsa.publicKeyCreate(priv);

    assert.strictEqual(dsa.paramsVerify(params), true);
    assert.strictEqual(dsa.privateKeyVerify(priv), true);
    assert.strictEqual(dsa.publicKeyVerify(pub), true);

    assert.strictEqual(dsa.paramsBits(params), 2048);
    assert.strictEqual(dsa.paramsScalarBits(params), 256);

    assert.strictEqual(dsa.privateKeyBits(priv), 2048);
    assert.strictEqual(dsa.privateKeyScalarBits(priv), 256);

    assert.strictEqual(dsa.publicKeyBits(pub), 2048);
    assert.strictEqual(dsa.publicKeyScalarBits(pub), 256);

    const msg = Buffer.alloc(32, 0xaa);
    const sig = dsa.sign(msg, priv);

    assert.strictEqual(dsa.verify(msg, sig, pub), true);

    const zero = Buffer.alloc(0);

    assert.strictEqual(dsa.verify(zero, sig, pub), false);
    assert.strictEqual(dsa.verify(msg, zero, pub), false);

    sig[0] ^= 1;

    assert.strictEqual(dsa.verify(msg, sig, pub), false);

    assert.bufferEqual(
      dsa.privateKeyImport(dsa.privateKeyExport(priv)),
      priv);
  });

  it('should sign and verify (DER)', () => {
    const size = FAST ? 2048 : 1024;
    const params = dsa.paramsGenerate(size);
    const priv = dsa.privateKeyCreate(params);
    const pub = dsa.publicKeyCreate(priv);
    const qsize = size < 2048 ? 20 : 32;

    const msg = Buffer.alloc(qsize, 0xaa);
    const sig = dsa.signDER(msg, priv);

    assert.strictEqual(dsa.verifyDER(msg, sig, pub), true);
    assert.strictEqual(dsa.verify(msg, sig, pub), false);

    const sig2 = dsa.signatureImport(sig, qsize);

    assert.strictEqual(dsa.verify(msg, sig2, pub), true);

    const sig3 = dsa.signatureExport(sig2);

    assert.bufferEqual(sig3, sig);

    sig[5] ^= 1;

    assert.strictEqual(dsa.verifyDER(msg, sig, pub), false);
  });

  it('should sign and verify (async)', async () => {
    const size = FAST ? 2048 : 1024;
    const params = await dsa.paramsGenerateAsync(size);
    const priv = dsa.privateKeyCreate(params);
    const pub = dsa.publicKeyCreate(priv);
    const qsize = size < 2048 ? 20 : 32;

    assert.strictEqual(dsa.privateKeyVerify(priv), true);
    assert.strictEqual(dsa.publicKeyVerify(pub), true);

    const msg = Buffer.alloc(qsize, 0xaa);
    const sig = dsa.sign(msg, priv);

    assert.strictEqual(dsa.verify(msg, sig, pub), true);

    sig[0] ^= 1;

    assert.strictEqual(dsa.verify(msg, sig, pub), false);
  });

  it('should do diffie hellman', () => {
    const params = createParams(P1024_160);
    const alice = dsa.privateKeyCreate(params);
    const alicePub = dsa.publicKeyCreate(alice);
    const bob = dsa.privateKeyCreate(params);
    const bobPub = dsa.publicKeyCreate(bob);

    const aliceSecret = dsa.derive(bobPub, alice);
    const bobSecret = dsa.derive(alicePub, bob);

    assert.bufferEqual(aliceSecret, bobSecret);
  });

  it('should parse SPKI', () => {
    const info = x509.SubjectPublicKeyInfo.fromPEM(PEM_TXT);
    assert(info.algorithm.algorithm.getKeyAlgorithmName() === 'DSA');
    assert(info.algorithm.parameters.node.type === 16); // SEQ
    assert(info.publicKey.type === 3); // BITSTRING

    const br = bio.read(info.algorithm.parameters.node.value);
    const p = asn1.Unsigned.read(br);
    const q = asn1.Unsigned.read(br);
    const g = asn1.Unsigned.read(br);
    const y = asn1.Unsigned.decode(info.publicKey.rightAlign());

    const key = dsa.publicKeyImport({
      p: p.value,
      q: q.value,
      g: g.value,
      y: y.value
    });

    assert(dsa.publicKeyVerify(key));
  });

  for (const [i, vector] of vectors.entries()) {
    const text = vector.sig.slice(0, 32) + '...';

    it(`should verify signature: ${text} (${i})`, () => {
      const msg = Buffer.from(vector.msg, 'hex');
      const sig = Buffer.from(vector.sig, 'hex');
      const pub = Buffer.from(vector.pub, 'hex');
      const priv = Buffer.from(vector.priv, 'hex');

      assert.bufferEqual(dsa.publicKeyCreate(priv), pub);
      assert.strictEqual(dsa.privateKeyVerify(priv), true);
      assert.strictEqual(dsa.publicKeyVerify(pub), true);

      assert.strictEqual(sig.length * 8, dsa.privateKeyScalarBits(priv) * 2);
      assert.strictEqual(sig.length * 8, dsa.publicKeyScalarBits(pub) * 2);

      assert.strictEqual(dsa.verify(msg, sig, pub), true);

      const sig2 = dsa.signatureExport(sig);
      const sig3 = dsa.signatureExport(sig, sig.length >>> 1);
      const sig4 = dsa.signatureImport(sig2, sig.length >>> 1);

      assert.bufferEqual(sig2, sig3);
      assert.bufferEqual(sig4, sig);

      assert.strictEqual(dsa.verifyDER(msg, sig2, pub), true);

      sig[i % sig.length] ^= 1;

      assert.strictEqual(dsa.verify(msg, sig, pub), false);
    });
  }

  it('should sign zero-length message', () => {
    const msg = Buffer.alloc(0);
    const params = createParams(P2048_256);
    const key = dsa.privateKeyCreate(params);
    const pub = dsa.publicKeyCreate(key);
    const sig = dsa.sign(msg, key);

    assert(dsa.verify(msg, sig, pub));
  });

  for (const [i, json] of custom.entries()) {
    const vector = json.map(s => Buffer.from(s, 'hex'));

    const [
      params,
      priv,
      pub,
      msg,
      sig,
      der
    ] = vector;

    it(`should parse and serialize key (${i})`, () => {
      assert.strictEqual(dsa.paramsVerify(params), true);
      assert.strictEqual(dsa.privateKeyVerify(priv), true);
      assert.strictEqual(dsa.publicKeyVerify(pub), true);
      assert.deepStrictEqual(dsa.publicKeyCreate(priv), pub);
    });

    it(`should recompute key (${i})`, () => {
      const {p, q, g, y, x} = dsa.privateKeyExport(priv);
      const k = dsa.privateKeyImport({ p, q, g, x });
      const info = dsa.privateKeyExport(k);

      assert.bufferEqual(info.p, p);
      assert.bufferEqual(info.q, q);
      assert.bufferEqual(info.g, g);
      assert.bufferEqual(info.y, y);
      assert.bufferEqual(info.x, x);
      assert.bufferEqual(k, priv);

      {
        const {p, q, g, y} = dsa.publicKeyExport(pub);

        assert.bufferEqual(p, info.p);
        assert.bufferEqual(q, info.q);
        assert.bufferEqual(g, info.g);
        assert.bufferEqual(y, info.y);
      }

      assert.bufferEqual(dsa.publicKeyImport(info), pub);
    });

    it(`should check signature (${i})`, () => {
      assert(dsa.signatureExport(sig), der);
      assert(dsa.signatureImport(der, sig.length >>> 1), sig);
    });

    it(`should sign and verify signature (${i})`, () => {
      const sig_ = dsa.sign(msg, priv);

      assert(dsa.verify(msg, sig_, pub));

      assert(dsa.verify(msg, sig, pub));

      msg[0] ^= 1;

      assert(!dsa.verify(msg, sig, pub));

      msg[0] ^= 1;
      sig[0] ^= 1;

      assert(!dsa.verify(msg, sig, pub));

      sig[0] ^= 1;
      pub[3] ^= 1;

      assert(!dsa.verify(msg, sig, pub));

      pub[3] ^= 1;

      assert(dsa.verify(msg, sig, pub));
    });

    it(`should sign and verify DER signature (${i})`, () => {
      const der_ = dsa.signDER(msg, priv);

      assert(dsa.verifyDER(msg, der_, pub));

      assert(dsa.verifyDER(msg, der, pub));

      msg[0] ^= 1;

      assert(!dsa.verifyDER(msg, der, pub));

      msg[0] ^= 1;
      der[3] ^= 1;

      assert(!dsa.verifyDER(msg, der, pub));

      der[3] ^= 1;
      pub[3] ^= 1;

      assert(!dsa.verifyDER(msg, der, pub));

      pub[3] ^= 1;

      assert(dsa.verifyDER(msg, der, pub));
    });
  }
});
