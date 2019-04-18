/*!
 * layout.js - indexer layout for bcoin
 * Copyright (c) 2018, the bcoin developers (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const bdb = require('bdb');

/*
 * Index database layout:
 * To be extended by indexer implementations.
 *
 *  V -> db version
 *  O -> flags
 *  h[height] -> block hash
 *  R -> index sync height
 */

const layout = {
  V: bdb.key('V'),
  O: bdb.key('O'),
  h: bdb.key('h', ['uint32']),
  R: bdb.key('R')
};

/*
 * Expose
 */

module.exports = layout;
