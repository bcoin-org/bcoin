/*!
 * ecdh.js - ECDH for bcrypto
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Resources:
 *   https://cr.yp.to/ecdh.html
 *   https://cr.yp.to/ecdh/curve25519-20060209.pdf
 *   https://tools.ietf.org/html/rfc7748
 */

'use strict';

const assert = require('../internal/assert');
const BN = require('../bn');
const elliptic = require('./elliptic');
const rng = require('../random');

/**
 * ECDH
 */

class ECDH {
  constructor(id, eid, pre) {
    assert(typeof id === 'string');
    assert(!eid || typeof eid === 'string');

    this.id = id;
    this.type = 'ecdh';
    this.eid = eid || null;
    this._pre = pre || null;
    this._curve = null;
    this._edwards = null;
    this.native = 0;
  }

  get curve() {
    if (!this._curve)
      this._curve = elliptic.curve(this.id);
    return this._curve;
  }

  get edwards() {
    if (this.eid && !this._edwards) {
      this._edwards = elliptic.curve(this.eid, this._pre);
      this._edwards.precompute(rng);
      this._pre = null;
    }
    return this._edwards;
  }

  get size() {
    return this.curve.fieldSize;
  }

  get bits() {
    return this.curve.fieldBits;
  }

  privateKeyGenerate() {
    const key = rng.randomBytes(this.curve.scalarSize);
    return this.curve.clamp(key);
  }

  privateKeyVerify(key) {
    assert(Buffer.isBuffer(key));
    return key.length === this.curve.scalarSize;
  }

  privateKeyExport(key, sign) {
    const pub = this.publicKeyCreate(key);
    const {x, y} = this.publicKeyExport(pub, sign);

    return {
      d: Buffer.from(key),
      x,
      y
    };
  }

  privateKeyImport(json) {
    assert(json && typeof json === 'object');

    const a = BN.decode(json.d, this.curve.endian);

    if (a.byteLength() > this.curve.scalarSize)
      throw new Error('Invalid private key.');

    return this.curve.encodeScalar(a);
  }

  publicKeyCreate(key) {
    const a = this.curve.decodeClamped(key);

    if (this.edwards && this.edwards.g.pre) {
      const A = this.edwards.g.mulBlind(a);
      const P = this.curve.pointFromEdwards(A);

      return P.encode();
    }

    const G = this.curve.g.toX();
    const A = G.mulBlind(a, rng);

    return A.encode();
  }

  publicKeyConvert(key, sign) {
    assert(sign == null || typeof sign === 'boolean');

    if (!this.edwards)
      throw new Error('No equivalent edwards curve.');

    const A = this.curve.decodePoint(key);
    const P = this.edwards.pointFromMont(A);

    if (sign != null) {
      if (P.isOdd() !== sign)
        return P.neg().encode();
    }

    return P.encode();
  }

  publicKeyFromUniform(bytes) {
    const u = this.curve.decodeUniform(bytes);
    const A = this.curve.pointFromUniform(u);

    return A.encode();
  }

  publicKeyToUniform(key, hint = rng.randomInt()) {
    const A = this.curve.decodePoint(key);
    const u = this.curve.pointToUniform(A, hint);

    return this.curve.encodeUniform(u, hint >>> 8);
  }

  publicKeyFromHash(bytes, pake = false) {
    const A = this.curve.pointFromHash(bytes, pake);

    return A.encode();
  }

  publicKeyToHash(key, subgroup = rng.randomInt()) {
    const A = this.curve.decodePoint(key);
    return this.curve.pointToHash(A, subgroup, rng);
  }

  publicKeyVerify(key) {
    assert(Buffer.isBuffer(key));

    let A;
    try {
      A = this.curve.decodeX(key);
    } catch (e) {
      return false;
    }

    return A.validate();
  }

  publicKeyIsSmall(key) {
    assert(Buffer.isBuffer(key));

    let A;
    try {
      A = this.curve.decodeX(key);
    } catch (e) {
      return false;
    }

    if (!A.validate())
      return false;

    return A.isSmall();
  }

  publicKeyHasTorsion(key) {
    assert(Buffer.isBuffer(key));

    let A;
    try {
      A = this.curve.decodeX(key);
    } catch (e) {
      return false;
    }

    if (!A.validate())
      return false;

    return A.hasTorsion();
  }

  publicKeyExport(key, sign) {
    const {x, y} = this.curve.decodePoint(key, sign);

    return {
      x: this.curve.encodeField(x.fromRed()),
      y: this.curve.encodeField(y.fromRed())
    };
  }

  publicKeyImport(json) {
    assert(json && typeof json === 'object');

    const x = BN.decode(json.x, this.curve.endian);

    if (x.cmp(this.curve.p) >= 0)
      throw new Error('Invalid point.');

    if (json.y != null) {
      const y = BN.decode(json.y, this.curve.endian);

      if (y.cmp(this.curve.p) >= 0)
        throw new Error('Invalid point.');

      const A = this.curve.point(x, y);

      if (!A.validate())
        throw new Error('Invalid point.');

      return A.encode();
    }

    const A = this.curve.pointFromX(x);

    return A.encode();
  }

  derive(pub, priv) {
    const A = this.curve.decodeX(pub);
    const a = this.curve.decodeClamped(priv);
    const P = A.mulBlind(a, rng);

    return P.encode();
  }
}

/*
 * Expose
 */

module.exports = ECDH;
