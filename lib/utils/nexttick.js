/*!
 * nexttick.js - setimmediate for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

module.exports = function nextTick(handler) {
  if (typeof handler !== 'function')
    throw new Error('callback must be a function.');

  setImmediate(handler);
};
