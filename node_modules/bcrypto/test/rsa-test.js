'use strict';

const assert = require('bsert');
const MD5 = require('../lib/md5');
const SHA1 = require('../lib/sha1');
const SHA256 = require('../lib/sha256');
const BLAKE2b256 = require('../lib/blake2b256');
const BLAKE2s256 = require('../lib/blake2s256');
const BN = require('../lib/bn');
const random = require('../lib/random');
const rsa = require('../lib/rsa');
const primes = require('../lib/internal/primes');
const base64 = require('../lib/encoding/base64');
const vectors = require('./data/rsa.json');
const custom = require('./data/sign/rsa.json');

const hashes = {
  SHA1,
  SHA256,
  BLAKE2B256: BLAKE2b256,
  BLAKE2S256: BLAKE2s256
};

const msg = SHA256.digest(Buffer.from('foobar'));
const zero = Buffer.alloc(0);

function fromJSON(json) {
  assert(json && typeof json === 'object');
  assert(json.kty === 'RSA');

  return rsa.publicKeyImport({
    n: base64.decodeURL(json.n),
    e: base64.decodeURL(json.e)
  });
}

function parseVector(json) {
  return json.map((item) => {
    if (typeof item !== 'string')
      return item;

    if (hashes[item])
      return hashes[item];

    return Buffer.from(item, 'hex');
  });
}

describe('RSA', function() {
  this.timeout(30000);

  it('should generate keypair', () => {
    const priv = rsa.privateKeyGenerate(1024);

    assert.bufferEqual(
      rsa.privateKeyImport(rsa.privateKeyExport(priv)),
      priv);

    const pub = rsa.publicKeyCreate(priv);

    assert.bufferEqual(
      rsa.publicKeyImport(rsa.publicKeyExport(pub)),
      pub);

    if (rsa.native === 2) {
      const {p, q} = rsa.privateKeyExport(priv);

      assert(primes.isProbablePrime(new BN(p), 20));
      assert(primes.isProbablePrime(new BN(q), 20));
    }
  });

  it('should generate keypair with custom exponent', () => {
    const priv = rsa.privateKeyGenerate(1024, 0x0100000001);
    const json = rsa.privateKeyExport(priv);

    assert.strictEqual(json.n.length, 128);
    assert.bufferEqual(json.e, Buffer.from('0100000001', 'hex'));
  });

  it('should generate keypair with custom exponent (async)', async () => {
    const priv = await rsa.privateKeyGenerateAsync(1024, 0x0100000001);
    const json = rsa.privateKeyExport(priv);

    assert.strictEqual(json.n.length, 128);
    assert.bufferEqual(json.e, Buffer.from('0100000001', 'hex'));
  });

  it('should sign and verify', () => {
    const bits = rsa.native < 2 ? 1024 : 2048;
    const priv = rsa.privateKeyGenerate(bits);
    const pub = rsa.publicKeyCreate(priv);

    assert(rsa.privateKeyVerify(priv));
    assert(rsa.publicKeyVerify(pub));

    const sig = rsa.sign(SHA256, msg, priv);
    assert(rsa.verify(SHA256, msg, sig, pub));

    assert(!rsa.verify(SHA256, zero, sig, pub));
    assert(!rsa.verify(SHA256, msg, zero, pub));

    sig[0] ^= 1;
    assert(!rsa.verify(SHA256, msg, sig, pub));
  });

  it('should veil/unveil', () => {
    const bits = rsa.native < 2 ? 1024 : 2048;
    const priv = rsa.privateKeyGenerate(bits);
    const pub = rsa.publicKeyCreate(priv);

    assert(rsa.privateKeyVerify(priv));
    assert(rsa.publicKeyVerify(pub));

    const s1 = rsa.sign(SHA256, msg, priv);
    const v1 = rsa.veil(s1, bits, pub);
    const s2 = rsa.unveil(v1, bits, pub);
    const v2 = rsa.veil(s1, bits + 8, pub);
    const s3 = rsa.unveil(v2, bits + 8, pub);
    const v3 = rsa.veil(s1, bits + 1024, pub);
    const s4 = rsa.unveil(v3, bits + 1024, pub);

    assert(v1.length === bits / 8);
    assert(v2.length === (bits + 8) / 8);
    assert(v3.length === (bits + 1024) / 8);

    assert(s1.length === bits / 8);
    assert(s2.length === bits / 8);
    assert(s3.length === bits / 8);
    assert(s4.length === bits / 8);

    assert(s2.equals(s1));
    assert(s3.equals(s1));
    assert(s4.equals(s1));

    assert(!v2.slice(0, (bits / 8)).equals(s1));
    assert(!v3.slice(0, (bits / 8)).equals(s1));
    assert(!v3.slice(-(bits / 8)).equals(s1));

    assert(rsa.verify(SHA256, msg, s1, pub));
    assert(rsa.verify(SHA256, msg, s2, pub));
    assert(rsa.verify(SHA256, msg, s3, pub));
    assert(rsa.verify(SHA256, msg, s4, pub));
  });

  it('should fail to verify non-canonical signature', () => {
    const bits = 1020;
    const priv = rsa.privateKeyGenerate(bits);
    const pub = rsa.publicKeyCreate(priv);

    assert(rsa.privateKeyVerify(priv));
    assert(rsa.publicKeyVerify(pub));

    const sig1 = rsa.sign(SHA256, msg, priv);
    const n = BN.decode(rsa.privateKeyExport(priv).n);
    const s = BN.decode(sig1);
    const sig2 = s.add(n).encode('be', (bits + 7) >> 3);

    assert(!rsa.verify(SHA256, msg, sig2, pub));
  });

  it('should sign and verify (PSS)', () => {
    const priv = rsa.privateKeyGenerate(1024);
    const pub = rsa.publicKeyCreate(priv);

    assert(rsa.privateKeyVerify(priv));
    assert(rsa.publicKeyVerify(pub));

    const sig1 = rsa.signPSS(SHA256, msg, priv, -1);
    assert(rsa.verifyPSS(SHA256, msg, sig1, pub));

    assert(!rsa.verifyPSS(SHA256, zero, sig1, pub));
    assert(!rsa.verifyPSS(SHA256, msg, zero, pub));

    sig1[0] ^= 1;
    assert(!rsa.verifyPSS(SHA256, msg, sig1, pub));

    const sig4 = rsa.signPSS(SHA256, msg, priv, 0);
    assert(rsa.verifyPSS(SHA256, msg, sig4, pub, 0));
    sig4[0] ^= 1;
    assert(!rsa.verifyPSS(SHA256, msg, sig4, pub, 0));
  });

  it('should sign and verify (async)', async () => {
    const bits = rsa.native < 2 ? 1024 : 2048;
    const priv = await rsa.privateKeyGenerateAsync(bits);
    const pub = rsa.publicKeyCreate(priv);

    assert(rsa.privateKeyVerify(priv));
    assert(rsa.publicKeyVerify(pub));

    const sig = rsa.sign(SHA256, msg, priv);
    const valid = rsa.verify(SHA256, msg, sig, pub);

    assert(valid);
  });

  it('should sign and verify (blake2b)', () => {
    const bits = rsa.native < 2 ? 1024 : 2048;
    const priv = rsa.privateKeyGenerate(bits);
    const pub = rsa.publicKeyCreate(priv);

    assert(rsa.privateKeyVerify(priv));
    assert(rsa.publicKeyVerify(pub));

    const sig = rsa.sign(BLAKE2b256, msg, priv);
    assert(rsa.verify(BLAKE2b256, msg, sig, pub));

    assert(!rsa.verify(BLAKE2b256, zero, sig, pub));
    assert(!rsa.verify(BLAKE2b256, msg, zero, pub));

    sig[0] ^= 1;
    assert(!rsa.verify(BLAKE2b256, msg, sig, pub));
  });

  it('should sign and verify (PSS) (blake2b)', () => {
    const priv = rsa.privateKeyGenerate(1024);
    const pub = rsa.publicKeyCreate(priv);

    assert(rsa.privateKeyVerify(priv));
    assert(rsa.publicKeyVerify(pub));

    const sig1 = rsa.signPSS(BLAKE2b256, msg, priv, -1);
    assert(rsa.verifyPSS(BLAKE2b256, msg, sig1, pub));

    assert(!rsa.verifyPSS(BLAKE2b256, zero, sig1, pub));
    assert(!rsa.verifyPSS(BLAKE2b256, msg, zero, pub));

    sig1[0] ^= 1;
    assert(!rsa.verifyPSS(BLAKE2b256, msg, sig1, pub));

    const sig2 = rsa.signPSS(BLAKE2b256, msg, priv, 0);
    assert(rsa.verifyPSS(BLAKE2b256, msg, sig2, pub, 0));
    sig2[0] ^= 1;
    assert(!rsa.verifyPSS(BLAKE2b256, msg, sig2, pub, 0));
  });

  it('should test signature padding (PKCS1v1.5)', () => {
    const priv = rsa.privateKeyGenerate(512);
    const pub = rsa.publicKeyCreate(priv);

    let msg, sig;

    do {
      msg = random.randomBytes(32);
      sig = rsa.sign(SHA256, msg, priv);
    } while (sig[0] !== 0x00);

    sig = sig.slice(1);

    assert(!rsa.verify(SHA256, msg, sig, pub));
  });

  it('should test PSS edge case', () => {
    const priv = rsa.privateKeyGenerate(513);
    const pub = rsa.publicKeyCreate(priv);
    const msg = random.randomBytes(16);
    const sig = rsa.signPSS(MD5, msg, priv);

    assert(rsa.verifyPSS(MD5, msg, sig, pub));
  });

  it('should test signature padding (PSS)', () => {
    const priv = rsa.privateKeyGenerate(512);
    const pub = rsa.publicKeyCreate(priv);

    let msg, sig;

    do {
      msg = random.randomBytes(16);
      sig = rsa.signPSS(MD5, msg, priv);
    } while (sig[0] !== 0x00);

    sig = sig.slice(1);

    assert(!rsa.verifyPSS(MD5, msg, sig, pub));
  });

  it('should encrypt and decrypt', () => {
    const priv = rsa.privateKeyGenerate(1024);
    const pub = rsa.publicKeyCreate(priv);
    const msg = Buffer.from('hello world');

    const ct = rsa.encrypt(msg, pub);

    assert.notBufferEqual(ct, msg);

    const pt = rsa.decrypt(ct, priv);

    assert.bufferEqual(pt, msg);
  });

  it('should encrypt and decrypt (OAEP)', () => {
    const priv = rsa.privateKeyGenerate(1024);
    const pub = rsa.publicKeyCreate(priv);
    const msg = Buffer.from('hello world');

    const ct = rsa.encryptOAEP(SHA1, msg, pub);

    assert.notBufferEqual(ct, msg);

    const pt = rsa.decryptOAEP(SHA1, ct, priv);

    assert.bufferEqual(pt, msg);
  });

  it('should encrypt and decrypt (OAEP, blake2b)', () => {
    const priv = rsa.privateKeyGenerate(1024);
    const pub = rsa.publicKeyCreate(priv);
    const msg = Buffer.from('hello world');

    const ct = rsa.encryptOAEP(BLAKE2b256, msg, pub);

    assert.notBufferEqual(ct, msg);

    const pt = rsa.decryptOAEP(BLAKE2b256, ct, priv);

    assert.bufferEqual(pt, msg);
  });

  for (const [i, vector] of vectors.entries()) {
    const hash = vector.hash === 'SHA1' ? SHA1 : SHA256;
    const msg = Buffer.from(vector.msg, 'hex');
    const sig = Buffer.from(vector.sig, 'hex');
    const key = fromJSON(vector.key);

    it(`should verify RSA vector #${i}`, () => {
      assert(rsa.publicKeyVerify(key));

      const m = hash.digest(msg);

      assert(rsa.verify(hash, m, sig, key));

      m[i % m.length] ^= 1;
      assert(!rsa.verify(hash, m, sig, key));
      m[i % m.length] ^= 1;
      assert(rsa.verify(hash, m, sig, key));

      sig[i % sig.length] ^= 1;
      assert(!rsa.verify(hash, m, sig, key));
      sig[i % sig.length] ^= 1;
      assert(rsa.verify(hash, m, sig, key));

      key[i % key.length] ^= 1;
      assert(!rsa.verify(hash, m, sig, key));
      key[i % key.length] ^= 1;
      assert(rsa.verify(hash, m, sig, key));
    });
  }

  {
    const vector = require('./data/rsa-other.json');
    const priv = Buffer.from(vector.priv, 'hex');
    const pub = rsa.publicKeyCreate(priv);
    const msg = Buffer.from('hello world');

    it('should verify PKCS1v1.5 signature', () => {
      const sig = Buffer.from(vector.sigPKCS1, 'hex');
      const result = rsa.verify(SHA1, SHA1.digest(msg), sig, pub);
      assert.strictEqual(result, true);
    });

    it('should decrypt PKCS1v1.5 type 2 ciphertext', () => {
      const ct = Buffer.from(vector.ctPKCS1, 'hex');

      const pt = rsa.decrypt(ct, priv);
      assert.bufferEqual(pt, msg);
    });

    it('should decrypt OAEP ciphertext', () => {
      const ct = Buffer.from(vector.ctOAEP, 'hex');

      const pt = rsa.decryptOAEP(SHA1, ct, priv);
      assert.bufferEqual(pt, msg);
    });

    it('should decrypt OAEP ciphertext (label=foo)', () => {
      const ct = Buffer.from(vector.ctOAEPLabelFoo, 'hex');

      const pt = rsa.decryptOAEP(SHA1, ct, priv, Buffer.from('foo'));
      assert.bufferEqual(pt, msg);
    });

    it('should verify PSS signature (auto)', () => {
      const sig = Buffer.from(vector.sigPSSAuto, 'hex');

      const result = rsa.verifyPSS(SHA1, SHA1.digest(msg), sig, pub, 0);
      assert.strictEqual(result, true);
    });

    it('should verify PSS signature (equals)', () => {
      const sig = Buffer.from(vector.sigPSSEquals, 'hex');

      const result = rsa.verifyPSS(SHA1, SHA1.digest(msg), sig, pub, -1);
      assert.strictEqual(result, true);
    });
  }

  for (const [i, json] of custom.entries()) {
    const vector = parseVector(json);

    const [
      priv,
      pub,
      hash,
      saltLen,
      msg,
      sig1,
      sig2,
      ct1,
      ct2
    ] = vector;

    const label = Buffer.from('bcrypto');

    it(`should parse and serialize key (${i})`, () => {
      assert(rsa.privateKeyVerify(priv));
      assert(rsa.publicKeyVerify(pub));
      assert.deepStrictEqual(rsa.publicKeyCreate(priv), pub);
    });

    it(`should recompute key (${i})`, () => {
      const {n, e, d, p, q, dp, dq, qi} = rsa.privateKeyExport(priv);
      const k1 = rsa.privateKeyImport({ p, q, e });
      const k2 = rsa.privateKeyImport({ p, q, d });
      const k3 = rsa.privateKeyImport({ n, e, d });
      const k4 = rsa.privateKeyImport({ n, e, d, p, q, dp, dq, qi });

      // Ensure we recovered the exponent.
      {
        const info = rsa.privateKeyExport(k2);

        assert.bufferEqual(info.e, e);
      }

      // Ensure we recovered the primes.
      {
        const info = rsa.privateKeyExport(k3);

        assert(p.compare(q) > 0);
        assert.bufferEqual(info.p, p);
        assert.bufferEqual(info.q, q);
      }

      assert.bufferEqual(rsa.sign(hash, msg, k1), sig1);
      assert.bufferEqual(rsa.sign(hash, msg, k2), sig1);
      assert.bufferEqual(rsa.sign(hash, msg, k3), sig1);
      assert.bufferEqual(rsa.sign(hash, msg, k4), sig1);

      {
        const info = rsa.publicKeyExport(pub);

        assert.bufferEqual(info.n, n);
        assert.bufferEqual(info.e, e);
      }

      assert.bufferEqual(rsa.publicKeyImport(rsa.privateKeyExport(k1)), pub);
      assert.bufferEqual(rsa.publicKeyImport(rsa.privateKeyExport(k2)), pub);
      assert.bufferEqual(rsa.publicKeyImport(rsa.privateKeyExport(k3)), pub);
      assert.bufferEqual(rsa.publicKeyImport(rsa.privateKeyExport(k4)), pub);
    });

    it(`should sign and verify PKCS1v1.5 signature (${i})`, () => {
      const sig = rsa.sign(hash, msg, priv);

      assert.bufferEqual(sig, sig1);

      assert(rsa.verify(hash, msg, sig, pub));

      msg[0] ^= 1;

      assert(!rsa.verify(hash, msg, sig, pub));

      msg[0] ^= 1;
      sig[0] ^= 1;

      assert(!rsa.verify(hash, msg, sig, pub));

      sig[0] ^= 1;
      pub[0] ^= 1;

      assert(!rsa.verify(hash, msg, sig, pub));

      pub[0] ^= 1;

      assert(rsa.verify(hash, msg, sig, pub));
    });

    it(`should sign and verify PSS signature (${i})`, () => {
      const sig = sig2;
      const sig_ = rsa.signPSS(hash, msg, priv, saltLen);

      assert(rsa.verifyPSS(hash, msg, sig_, pub, saltLen));

      assert(rsa.verifyPSS(hash, msg, sig, pub, saltLen));

      msg[0] ^= 1;

      assert(!rsa.verifyPSS(hash, msg, sig, pub, saltLen));

      msg[0] ^= 1;
      sig[0] ^= 1;

      assert(!rsa.verifyPSS(hash, msg, sig, pub, saltLen));

      sig[0] ^= 1;
      pub[0] ^= 1;

      assert(!rsa.verifyPSS(hash, msg, sig, pub, saltLen));

      pub[0] ^= 1;

      assert(rsa.verifyPSS(hash, msg, sig, pub, saltLen));
    });

    it(`should encrypt and decrypt PKCS1v1.5 type 2 ciphertext (${i})`, () => {
      assert.bufferEqual(rsa.decrypt(ct1, priv), msg);
      assert.bufferEqual(rsa.decrypt(rsa.encrypt(msg, pub), priv), msg);
    });

    it(`should encrypt and decrypt OAEP ciphertext (${i})`, () => {
      assert.bufferEqual(rsa.decryptOAEP(hash, ct2, priv, label), msg);
      assert.bufferEqual(rsa.decryptOAEP(hash,
        rsa.encryptOAEP(hash, msg, pub, label), priv, label), msg);
    });
  }
});
