/*!
 * layout.js - mempool data layout for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

/*
 * Database Layout:
 *   R -> tip hash
 *   e[id][hash] -> entry
 */

var layout = {
  R: new Buffer([0x52]),
  e: function e(id, hash) {
    var key = new Buffer(37);
    key[0] = 0x65;
    key.writeUInt32BE(id, 1, true);
    write(key, hash, 5);
    return key;
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
