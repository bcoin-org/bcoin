/*!
 * layout.js - blockchain data layout for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');

/*
 * Database Layout:
 *   R -> tip hash
 *   O -> chain options
 *   e[hash] -> entry
 *   h[hash] -> height
 *   H[height] -> hash
 *   n[hash] -> next hash
 *   p[hash] -> tip index
 *   b[hash] -> block
 *   t[hash] -> extended tx
 *   c[hash] -> coins
 *   u[hash] -> undo coins
 *   v -> versionbits deployments
 *   v[bit][hash] -> versionbits state
 *   T[addr-hash][hash] -> dummy (tx by address)
 *   C[addr-hash][hash][index] -> dummy (coin by address)
 *   W+T[witaddr-hash][hash] -> dummy (tx by address)
 *   W+C[witaddr-hash][hash][index] -> dummy (coin by address)
 */

const layout = {
  binary: true,
  R: Buffer.from([0x52]),
  O: Buffer.from([0x4f]),
  V: Buffer.from([0x76]),
  e: function e(hash) {
    return pair(0x65, hash);
  },
  h: function h(hash) {
    return pair(0x68, hash);
  },
  H: function H(height) {
    return ipair(0x48, height);
  },
  n: function n(hash) {
    return pair(0x6e, hash);
  },
  p: function p(hash) {
    return pair(0x70, hash);
  },
  b: function b(hash) {
    return pair(0x62, hash);
  },
  t: function t(hash) {
    return pair(0x74, hash);
  },
  c: function c(hash, index) {
    return bpair(0x63, hash, index);
  },
  u: function u(hash) {
    return pair(0x75, hash);
  },
  v: function v(bit, hash) {
    const key = Buffer.allocUnsafe(1 + 1 + 32);
    assert(typeof bit === 'number');
    key[0] = 0x76;
    key[1] = bit;
    write(key, hash, 2);
    return key;
  },
  vv: function vv(key) {
    assert(Buffer.isBuffer(key));
    assert(key.length === 34);
    return [key[1], key.toString('hex', 2, 34)];
  },
  T: function T(addr, hash) {
    let len = addr.length;

    if (typeof addr === 'string')
      len /= 2;

    let key;
    if (len === 32) {
      key = Buffer.allocUnsafe(65);
      key[0] = 0xab; // W + T
      write(key, addr, 1);
      write(key, hash, 33);
    } else if (len === 20) {
      key = Buffer.allocUnsafe(53);
      key[0] = 0x54; // T
      write(key, addr, 1);
      write(key, hash, 21);
    } else {
      assert(false);
    }

    return key;
  },
  C: function C(addr, hash, index) {
    let len = addr.length;

    assert(typeof index === 'number');

    if (typeof addr === 'string')
      len /= 2;

    let key;
    if (len === 32) {
      key = Buffer.allocUnsafe(69);
      key[0] = 0x9a; // W + C
      write(key, addr, 1);
      write(key, hash, 33);
      key.writeUInt32BE(index, 65, true);
    } else if (len === 20) {
      key = Buffer.allocUnsafe(57);
      key[0] = 0x43; // C
      write(key, addr, 1);
      write(key, hash, 21);
      key.writeUInt32BE(index, 53, true);
    } else {
      assert(false);
    }

    return key;
  },
  pp: function pp(key) {
    assert(Buffer.isBuffer(key));
    assert(key.length === 33);
    return key.toString('hex', 1, 33);
  },
  Cc: function Cc(key) {
    assert(Buffer.isBuffer(key));

    let hash, index;
    if (key.length === 69) {
      hash = key.toString('hex', 33, 65);
      index = key.readUInt32BE(65, 0);
    } else if (key.length === 57) {
      hash = key.toString('hex', 21, 53);
      index = key.readUInt32BE(53, 0);
    } else {
      assert(false);
    }

    return [hash, index];
  },
  Tt: function Tt(key) {
    assert(Buffer.isBuffer(key));

    if (key.length === 65)
      return key.toString('hex', 33, 65);

    assert(key.length === 53);
    return key.toString('hex', 21, 53);
  }
};

/*
 * Helpers
 */

function write(data, str, off) {
  if (Buffer.isBuffer(str))
    return str.copy(data, off);
  assert(typeof str === 'string');
  return data.write(str, off, 'hex');
}

function pair(prefix, hash) {
  const key = Buffer.allocUnsafe(33);
  key[0] = prefix;
  write(key, hash, 1);
  return key;
}

function ipair(prefix, num) {
  const key = Buffer.allocUnsafe(5);
  assert(typeof num === 'number');
  key[0] = prefix;
  key.writeUInt32BE(num, 1, true);
  return key;
}

function bpair(prefix, hash, index) {
  const key = Buffer.allocUnsafe(37);
  assert(typeof index === 'number');
  key[0] = prefix;
  write(key, hash, 1);
  key.writeUInt32BE(index, 33, true);
  return key;
}

/*
 * Expose
 */

module.exports = layout;
