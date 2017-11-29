/*!
 * layout.js - mempool data layout for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const Key = require('bdb/lib/key');

/*
 * Database Layout:
 *   R -> tip hash
 *   V -> db version
 *   e[id][hash] -> entry
 */

const R = new Key('R');
const V = new Key('v');
const F = new Key('F');
const e = new Key('e', ['hash256']);

const layout = {
  binary: true,
  R: R.build.bind(R),
  V: V.build.bind(V),
  F: F.build.bind(F),
  e: e.build.bind(e),
  ee: e.parse.bind(e)
};

/*
 * Expose
 */

module.exports = layout;
