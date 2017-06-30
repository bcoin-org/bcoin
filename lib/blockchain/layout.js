/*!
 * layout.js - blockchain data layout for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

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
  c: function c(hash) {
    return pair(0x63, hash);
  },
  u: function u(hash) {
    return pair(0x75, hash);
  },
  v: function v(bit, hash) {
    let key = Buffer.allocUnsafe(1 + 1 + 32);
    key[0] = 0x76;
    key[1] = bit;
    write(key, hash, 2);
    return key;
  },
  vv: function vv(key) {
    return [key[1], key.toString('hex', 2, 34)];
  },
  T: function T(address, hash) {
    let len = address.length;
    let key;

    if (typeof address === 'string')
      len /= 2;

    if (len === 32) {
      key = Buffer.allocUnsafe(65);
      key[0] = 0xab; // W + T
      write(key, address, 1);
      write(key, hash, 33);
    } else {
      key = Buffer.allocUnsafe(53);
      key[0] = 0x54; // T
      write(key, address, 1);
      write(key, hash, 21);
    }

    return key;
  },
  C: function C(address, hash, index) {
    let len = address.length;
    let key;

    if (typeof address === 'string')
      len /= 2;

    if (len === 32) {
      key = Buffer.allocUnsafe(69);
      key[0] = 0x9a; // W + C
      write(key, address, 1);
      write(key, hash, 33);
      key.writeUInt32BE(index, 65, true);
    } else {
      key = Buffer.allocUnsafe(57);
      key[0] = 0x43; // C
      write(key, address, 1);
      write(key, hash, 21);
      key.writeUInt32BE(index, 53, true);
    }

    return key;
  },
  pp: function aa(key) {
    return key.toString('hex', 1, 33);
  },
  Cc: function Cc(key) {
    let hash, index;

    if (key.length === 69) {
      hash = key.toString('hex', 33, 65);
      index = key.readUInt32BE(65, 0);
    } else {
      hash = key.toString('hex', 21, 53);
      index = key.readUInt32BE(53, 0);
    }

    return [hash, index];
  },
  Tt: function Tt(key) {
    return key.length === 65
      ? key.toString('hex', 33, 65)
      : key.toString('hex', 21, 53);
  }
};

/*
 * Helpers
 */

function write(data, str, off) {
  if (Buffer.isBuffer(str))
    return str.copy(data, off);
  data.write(str, off, 'hex');
}

function pair(prefix, hash) {
  let key = Buffer.allocUnsafe(33);
  key[0] = prefix;
  write(key, hash, 1);
  return key;
}

function ipair(prefix, num) {
  let key = Buffer.allocUnsafe(5);
  key[0] = prefix;
  key.writeUInt32BE(num, 1, true);
  return key;
}

/*
 * Expose
 */

module.exports = layout;
