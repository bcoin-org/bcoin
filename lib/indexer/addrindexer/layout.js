/*!
 * layout.js - addrindexer layout for bcoin
 * Copyright (c) 2018, the bcoin developers (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const bdb = require('bdb');

/*
 * AddrIndexer Database Layout:
 *  T[addr-hash][hash] -> dummy (tx by address)
 *  C[addr-hash][hash][index] -> dummy (coin by address)
*/

const layout = Object.assign({
  T: bdb.key('T', ['hash', 'hash256']),
  C: bdb.key('C', ['hash', 'hash256', 'uint32'])
}, require('../layout'));

/*
 * Expose
 */

module.exports = layout;
