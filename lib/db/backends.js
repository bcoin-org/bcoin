/**
 * backends.js - database backends for bcoin
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

exports.get = function get(name) {
  if (name === 'rbt')
    return require('./rbt');

  try {
    return require(name);
  } catch (e) {
    throw new Error('Database backend "' + name + '" not found.');
  }
};
