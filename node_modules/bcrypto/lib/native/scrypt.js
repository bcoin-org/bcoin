/*!
 * scrypt.js - scrypt for bcrypto
 * Copyright (c) 2017-2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const binding = require('./binding').scrypt;

exports.native = 2;

exports.derive = binding.derive;

exports.deriveAsync = function deriveAsync(passwd, salt, N, r, p, len) {
  return new Promise((resolve, reject) => {
    const cb = (err, key) => {
      if (err) {
        reject(err);
        return;
      }
      resolve(key);
    };

    try {
      binding.deriveAsync(passwd, salt, N, r, p, len, cb);
    } catch (e) {
      reject(e);
    }
  });
};
