/*!
 * nexttick.js - setimmediate for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

module.exports = typeof setImmediate !== 'function'
  ? process.nextTick
  : setImmediate;
