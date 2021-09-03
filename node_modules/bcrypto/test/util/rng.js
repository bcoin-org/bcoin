'use strict';

const assert = require('bsert');
const SHA256 = require('../../lib/sha256');

// Super dumb deterministic RNG.
class RNG {
  constructor() {
    this.prev = Buffer.alloc(32, 0x00);
  }

  randomBytes(len) {
    assert((len >>> 0) === len);

    const out = Buffer.alloc(len);

    let pos = 0;

    while (pos < len) {
      this.prev = SHA256.digest(this.prev);
      pos += this.prev.copy(out, pos);
    }

    return out;
  }

  randomInt() {
    return this.randomBytes(4).readUInt32LE(0);
  }

  randomRange(min, max) {
    assert((min >>> 0) === min);
    assert((max >>> 0) === max);
    assert(max >= min);

    const space = max - min;

    if (space === 0)
      return min;

    return (this.randomInt() % space) + min;
  }

  privateKeyGenerate(curve) {
    assert(curve && typeof curve.id === 'string');
    assert((curve.size >>> 0) === curve.size);
    assert(typeof curve.privateKeyGenerate === 'function');

    if (curve.type === 'ecdsa') {
      let key;

      do {
        key = this.randomBytes(curve.size);
      } while (!curve.privateKeyVerify(key));

      return key;
    }

    return this.randomBytes(curve.size);
  }

  scalarGenerate(curve) {
    assert(curve && typeof curve.id === 'string');
    assert((curve.bits >>> 0) === curve.bits);
    assert(typeof curve.scalarGenerate === 'function');

    const key = this.randomBytes((curve.bits + 7) >>> 3);

    return curve.scalarClamp(key);
  }
}

module.exports = RNG;
