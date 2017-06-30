/*!
 * layout.js - mempool data layout for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

/*
 * Database Layout:
 *   R -> tip hash
 *   V -> db version
 *   e[id][hash] -> entry
 */

const layout = {
  binary: true,
  R: Buffer.from([0x52]),
  V: Buffer.from([0x76]),
  F: Buffer.from([0x46]),
  e: function e(hash) {
    let key = Buffer.allocUnsafe(33);
    key[0] = 0x65;
    write(key, hash, 1);
    return key;
  },
  ee: function ee(key) {
    return key.toString('hex', 1, 33);
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

/*
 * Expose
 */

module.exports = layout;
