/*!
 * ecdsa.js - wrapper for elliptic
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on indutny/elliptic:
 *   Copyright (c) 2014, Fedor Indutny (MIT License).
 *   https://github.com/indutny/elliptic
 */

'use strict';

const assert = require('bsert');
const BN = require('../bn.js');
const eckey = require('../internal/eckey');
const Signature = require('../internal/signature');
const asn1 = require('../encoding/asn1');
const sec1 = require('../encoding/sec1');
const pkcs8 = require('../encoding/pkcs8');
const x509 = require('../encoding/x509');
const rng = require('../random');
const Schnorr = require('./schnorr');
const DRBG = require('../drbg');
const curves = require('./curves');

/**
 * ECDSA
 */

class ECDSA {
  constructor(name, hash, pre) {
    assert(typeof name === 'string');
    assert(hash);

    this.id = name;
    this.type = 'short';
    this.hash = hash;
    this._pre = pre || null;
    this._curve = null;
    this._schnorr = null;
    this.native = 0;
  }

  get curve() {
    if (!this._curve) {
      this._curve = new curves[this.id](this._pre);
      this._curve.precompute(rng);
      this._pre = null;
    }
    return this._curve;
  }

  get schnorr() {
    if (!this._schnorr)
      this._schnorr = new Schnorr(this.curve, this.hash);
    return this._schnorr;
  }

  get size() {
    return this.curve.size;
  }

  get bits() {
    return this.curve.bits;
  }

  get zero() {
    return this.curve.zeroRaw;
  }

  get order() {
    return this.curve.orderRaw;
  }

  get half() {
    return this.curve.halfRaw;
  }

  privateKeyGenerate() {
    const key = Buffer.allocUnsafe(this.size);

    do {
      rng.randomFill(key, 0, this.size);
    } while (!this.privateKeyVerify(key));

    return key;
  }

  privateKeyVerify(key) {
    assert(Buffer.isBuffer(key));

    if (key.length !== this.size)
      return false;

    if (key.equals(this.zero))
      return false;

    return key.compare(this.order) < 0;
  }

  privateKeyExport(key, compress) {
    const pub = this.publicKeyCreate(key, compress);
    return new sec1.ECPrivateKey(1, key, this.id, pub).encode();
  }

  privateKeyImport(raw) {
    const key = sec1.ECPrivateKey.decode(raw);
    const curve = key.namedCurveOID.toString();

    assert(key.version.toNumber() === 1);
    assert(curve === asn1.objects.curves[this.id]
        || curve === asn1.objects.NONE);

    const priv = key.privateKey.value;

    if (!this.privateKeyVerify(priv))
      throw new Error('Invalid private key.');

    return priv;
  }

  privateKeyExportPKCS8(key, compress) {
    const pub = this.publicKeyCreate(key, compress);
    const curve = asn1.objects.NONE;

    // https://tools.ietf.org/html/rfc5915
    return new pkcs8.PrivateKeyInfo(
      0,
      asn1.objects.keyAlgs.ECDSA,
      new asn1.OID(asn1.objects.curves[this.id]),
      new sec1.ECPrivateKey(1, key, curve, pub).encode()
    ).encode();
  }

  privateKeyImportPKCS8(raw) {
    const pki = pkcs8.PrivateKeyInfo.decode(raw);
    const {algorithm, parameters} = pki.algorithm;

    assert(pki.version.toNumber() === 0);
    assert(algorithm.toString() === asn1.objects.keyAlgs.ECDSA);
    assert(parameters.node.type === asn1.types.OID);
    assert(parameters.node.toString() === asn1.objects.curves[this.id]);

    return this.privateKeyImport(pki.privateKey.value);
  }

  privateKeyExportJWK(key) {
    return eckey.privateKeyExportJWK(this, key);
  }

  privateKeyImportJWK(json) {
    return eckey.privateKeyImportJWK(this, json);
  }

  privateKeyTweakAdd(key, tweak) {
    const t = this.curve.decodeScalar(tweak);

    if (t.cmp(this.curve.n) >= 0)
      throw new Error('Invalid scalar.');

    const a = this.curve.decodeScalar(key);

    if (a.isZero() || a.cmp(this.curve.n) >= 0)
      throw new Error('Invalid private key.');

    const T = a.iadd(t).iumod(this.curve.n);

    if (T.isZero())
      throw new Error('Invalid private key.');

    return this.curve.encodeScalar(T);
  }

  privateKeyTweakMul(key, tweak) {
    const t = this.curve.decodeScalar(tweak);

    if (t.isZero() || t.cmp(this.curve.n) >= 0)
      throw new Error('Invalid scalar.');

    const a = this.curve.decodeScalar(key);

    if (a.isZero() || a.cmp(this.curve.n) >= 0)
      throw new Error('Invalid private key.');

    const T = a.imul(t).iumod(this.curve.n);

    if (T.isZero())
      throw new Error('Invalid private key.');

    return this.curve.encodeScalar(T);
  }

  privateKeyNegate(key) {
    const a = this.curve.decodeScalar(key);

    if (a.cmp(this.curve.n) >= 0)
      throw new Error('Invalid private key.');

    const T = a.isZero() ? a : this.curve.n.sub(a);

    return this.curve.encodeScalar(T);
  }

  privateKeyInverse(key) {
    const a = this.curve.decodeScalar(key);

    if (a.isZero() || a.cmp(this.curve.n) >= 0)
      throw new Error('Invalid private key.');

    const T = a.invm(this.curve.n);

    if (T.isZero())
      throw new Error('Invalid private key.');

    return this.curve.encodeScalar(T);
  }

  publicKeyCreate(key, compress) {
    const a = this.curve.decodeScalar(key);

    if (a.isZero() || a.cmp(this.curve.n) >= 0)
      throw new Error('Invalid private key.');

    const A = this.curve.g.mulBlind(a);

    return A.encode(compress);
  }

  publicKeyConvert(key, compress) {
    const A = this.curve.decodePoint(key);
    return A.encode(compress);
  }

  publicKeyVerify(key) {
    assert(Buffer.isBuffer(key));

    try {
      this.curve.decodePoint(key);
    } catch (e) {
      return false;
    }

    return true;
  }

  publicKeyExport(key) {
    return this.publicKeyConvert(key, false).slice(1);
  }

  publicKeyImport(raw, compress) {
    assert(Buffer.isBuffer(raw));
    assert(raw.length === this.size * 2);

    const key = Buffer.allocUnsafe(1 + raw.length);
    key[0] = 0x04;
    raw.copy(key, 1);

    return this.publicKeyConvert(key, compress);
  }

  publicKeyExportSPKI(key, compress) {
    // https://tools.ietf.org/html/rfc5480
    return new x509.SubjectPublicKeyInfo(
      asn1.objects.keyAlgs.ECDSA,
      new asn1.OID(asn1.objects.curves[this.id]),
      this.publicKeyConvert(key, compress)
    ).encode();
  }

  publicKeyImportSPKI(raw, compress) {
    const spki = x509.SubjectPublicKeyInfo.decode(raw);
    const {algorithm, parameters} = spki.algorithm;

    assert(algorithm.toString() === asn1.objects.keyAlgs.ECDSA);
    assert(parameters.node.type === asn1.types.OID);
    assert(parameters.node.toString() === asn1.objects.curves[this.id]);

    return this.publicKeyConvert(spki.publicKey.rightAlign(), compress);
  }

  publicKeyExportJWK(key) {
    return eckey.publicKeyExportJWK(this, key);
  }

  publicKeyImportJWK(json, compress) {
    return eckey.publicKeyImportJWK(this, json, compress);
  }

  publicKeyTweakAdd(key, tweak, compress) {
    const t = this.curve.decodeScalar(tweak);

    if (t.cmp(this.curve.n) >= 0)
      throw new Error('Invalid scalar.');

    const A = this.curve.decodePoint(key);
    const T = this.curve.g.mul(t).add(A);

    return T.encode(compress);
  }

  publicKeyTweakMul(key, tweak, compress) {
    const t = this.curve.decodeScalar(tweak);

    if (t.isZero() || t.cmp(this.curve.n) >= 0)
      throw new Error('Invalid private key.');

    const A = this.curve.decodePoint(key);
    const T = A.mul(t);

    return T.encode(compress);
  }

  publicKeyAdd(key1, key2, compress) {
    const A1 = this.curve.decodePoint(key1);
    const A2 = this.curve.decodePoint(key2);
    const T = A1.add(A2);

    return T.encode(compress);
  }

  publicKeyNegate(key, compress) {
    const A = this.curve.decodePoint(key);
    const T = A.neg();

    return T.encode(compress);
  }

  signatureExport(sig) {
    return Signature.toDER(sig, this.size);
  }

  signatureImport(sig) {
    return Signature.toRS(sig, this.size);
  }

  _sign(msg, key) {
    assert(Buffer.isBuffer(msg));

    const N = this.curve.n;
    const Nh = this.curve.nh;
    const G = this.curve.g;
    const bytes = N.byteLength();

    const a = this.curve.decodeScalar(key);

    if (a.isZero() || a.cmp(N) >= 0)
      throw new Error('Invalid private key.');

    // https://tools.ietf.org/html/rfc6979#section-3.2
    const m = this._reduce(msg);
    const nonce = m.encode(this.curve.endian, bytes);
    const drbg = new DRBG(this.hash, key, nonce);

    for (;;) {
      const k = this._truncate(drbg.generate(bytes));

      if (k.isZero() || k.cmp(N) >= 0)
        continue;

      const kp = G.mulBlind(k);

      if (kp.isInfinity())
        continue;

      const kpX = kp.getX();
      const r = kpX.umod(N);

      if (r.isZero())
        continue;

      // Reasoning: fermat's little theorem
      // has better constant-time properties
      // than an EGCD.
      const ki = k.finvm(N);

      // Without blinding factor.
      // s := ((r * a + m) * k^-1) mod n
      // let s = r.mul(a).iumod(N)
      //          .iadd(m).iumod(N)
      //          .imul(ki).iumod(N);

      // Blinding factor (precomputed).
      const [b, bi] = this.curve.getBlinding();

      // ra := (b * a * r) mod n
      const ra = b.mul(a).iumod(N)
                  .imul(r).iumod(N);

      // bm := (b * m) mod n
      const bm = b.mul(m).iumod(N);

      // s := ((b * a * r) + (b * m)) mod n
      // s := (s * k^-1) mod n
      // s := (s * b^-1) mod n
      let s = ra.iadd(bm).iumod(N)
                .imul(ki).iumod(N)
                .imul(bi).iumod(N);

      if (s.isZero())
        continue;

      let param = (kp.getY().isOdd() ? 1 : 0)
                | (kpX.cmp(r) !== 0 ? 2 : 0);

      // Use complement of `s`, if it is > `n / 2`.
      if (s.cmp(Nh) > 0) {
        s = N.sub(s);
        param ^= 1;
      }

      const sig = new Signature();

      sig.r = this.curve.encodeScalar(r);
      sig.s = this.curve.encodeScalar(s);
      sig.param = param;

      return sig;
    }
  }

  sign(msg, key) {
    const sig = this._sign(msg, key);
    return sig.encode(this.size);
  }

  signRecoverable(msg, key) {
    const sig = this._sign(msg, key);
    return {
      signature: sig.encode(this.size),
      recovery: sig.param
    };
  }

  signDER(msg, key) {
    const sig = this._sign(msg, key);
    return sig.toDER(this.size);
  }

  signRecoverableDER(msg, key) {
    const sig = this._sign(msg, key);
    return {
      signature: sig.toDER(this.size),
      recovery: sig.param
    };
  }

  _verify(msg, sig, key) {
    const N = this.curve.n;
    const G = this.curve.g;
    const m = this._reduce(msg);
    const A = this.curve.decodePoint(key);

    // Perform primitive values validation.
    const r = this.curve.decodeScalar(sig.r);
    const s = this.curve.decodeScalar(sig.s);

    if (r.isZero() || r.cmp(N) >= 0)
      return false;

    if (s.isZero() || s.cmp(N) >= 0)
      return false;

    // Validate signature.
    const si = s.invm(N);
    const u1 = m.imul(si).iumod(N);
    const u2 = r.mul(si).iumod(N);

    if (this.curve.maxwellTrick) {
      // NOTE: Greg Maxwell's trick, inspired by:
      // https://git.io/vad3K
      const p = G.jmulAdd(u1, A, u2);

      if (p.isInfinity())
        return false;

      // Compare `p.x` of Jacobian point with `r`,
      // this will do `p.x == r * p.z^2` instead
      // of multiplying `p.x` by the inverse of
      // `p.z^2`.
      return p.eqXToP(r);
    }

    const p = G.mulAdd(u1, A, u2);

    if (p.isInfinity())
      return false;

    return p.getX().umod(N).cmp(r) === 0;
  }

  verify(msg, sig, key) {
    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(sig));
    assert(Buffer.isBuffer(key));

    if (sig.length !== this.size * 2)
      return false;

    const s = Signature.decode(sig, this.size);

    try {
      return this._verify(msg, s, key);
    } catch (e) {
      return false;
    }
  }

  verifyDER(msg, sig, key) {
    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(sig));
    assert(Buffer.isBuffer(key));

    let s;
    try {
      s = Signature.fromDER(sig, this.size);
    } catch (e) {
      return false;
    }

    try {
      return this._verify(msg, s, key);
    } catch (e) {
      return false;
    }
  }

  _recover(msg, sig, param) {
    const P = this.curve.p;
    const N = this.curve.n;
    const G = this.curve.g;
    const m = this._reduce(msg);
    const r = this.curve.decodeScalar(sig.r);
    const s = this.curve.decodeScalar(sig.s);

    if (r.isZero() || r.cmp(N) >= 0)
      throw new Error('Invalid R value.');

    if (s.isZero() || s.cmp(N) >= 0)
      throw new Error('Invalid S value.');

    // A set LSB signifies that the y-coordinate is odd.
    const isOddY = param & 1;
    const isSecondKey = param >> 1;

    if (r.cmp(P.umod(N)) >= 0 && isSecondKey)
      throw new Error('Invalid R value.');

    let x = r;

    // 1.1. Let x = r + jn.
    if (isSecondKey)
      x = x.add(N);

    const r2 = this.curve.pointFromX(x, isOddY);
    const ri = r.invm(N);
    const s1 = N.sub(m).imul(ri).iumod(N);
    const s2 = s.imul(ri).iumod(N);

    // 1.6.1 Compute Q = r^-1 (sR -  eG)
    //               Q = r^-1 (sR + -eG).
    const Q = G.mulAdd(s1, r2, s2);

    if (Q.isInfinity())
      throw new Error('Invalid point.');

    return Q;
  }

  recover(msg, sig, param, compress) {
    if (param == null)
      param = 0;

    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(sig));
    assert((param >>> 0) === param);
    assert((param & 3) === param, 'The recovery param is more than two bits.');

    if (sig.length !== this.size * 2)
      return null;

    const s = Signature.decode(sig, this.size);

    let point;
    try {
      point = this._recover(msg, s, param);
    } catch (e) {
      return null;
    }

    return point.encode(compress);
  }

  recoverDER(msg, sig, param, compress) {
    if (param == null)
      param = 0;

    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(sig));
    assert((param >>> 0) === param);
    assert((param & 3) === param, 'The recovery param is more than two bits.');

    let s;
    try {
      s = Signature.fromDER(sig, this.size);
    } catch (e) {
      return null;
    }

    let point;
    try {
      point = this._recover(msg, s, param);
    } catch (e) {
      return null;
    }

    return point.encode(compress);
  }

  derive(pub, priv, compress) {
    const a = this.curve.decodeScalar(priv);

    if (a.isZero() || a.cmp(this.curve.n) >= 0)
      throw new Error('Invalid private key.');

    const A = this.curve.decodePoint(pub);
    const point = A.mulBlind(a, rng);

    if (point.isInfinity())
      throw new Error('Invalid public key.');

    return point.encode(compress);
  }

  isLowS(sig) {
    return Signature.isLowS(sig, this.size, this.half);
  }

  isLowDER(sig) {
    return Signature.isLowDER(sig, this.size, this.half);
  }

  /*
   * Compat
   */

  generatePrivateKey() {
    return this.privateKeyGenerate();
  }

  fromDER(sig) {
    return this.signatureImport(sig);
  }

  toDER(sig) {
    return this.signatureExport(sig);
  }

  ecdh(pub, priv, compress) {
    return this.derive(pub, priv, compress);
  }

  /*
   * Helpers
   */

  _truncate(msg) {
    assert(Buffer.isBuffer(msg));

    const bits = this.curve.n.bitLength();
    const bytes = (bits + 7) >>> 3;

    if (msg.length > bytes)
      msg = msg.slice(0, bytes);

    const m = BN.decode(msg, this.curve.endian);
    const d = msg.length * 8 - bits;

    if (d > 0)
      m.iushrn(d);

    return m;
  }

  _reduce(msg) {
    return this._truncate(msg).iumod(this.curve.n);
  }
}

/*
 * Expose
 */

module.exports = ECDSA;
