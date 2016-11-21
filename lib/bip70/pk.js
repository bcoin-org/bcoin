/*!
 * pk.js - public key algorithms for bcoin
 * Copyright (c) 2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var pk = require('../crypto/pk');
var co = require('../utils/co');

exports._verify = function verify(hash, msg, sig, key) {
  switch (key.alg) {
    case 'dsa':
      return pk.dsa.verify(hash, msg, sig, key.data, key.params);
    case 'rsa':
      return pk.rsa.verify(hash, msg, sig, key.data);
    case 'ecdsa':
      return pk.ecdsa.verify(key.curve, hash, msg, sig, key.data);
    default:
      throw new Error('Unsupported algorithm.');
  }
};

exports.verify = function verify(hash, msg, sig, key) {
  try {
    return exports._verify(hash, msg, sig, key);
  } catch (e) {
    return false;
  }
};

exports.sign = function sign(hash, msg, key) {
  switch (key.alg) {
    case 'dsa':
      return pk.dsa.sign(hash, msg, key.data, key.params);
    case 'rsa':
      return pk.rsa.sign(hash, msg, key.data);
    case 'ecdsa':
      return pk.ecdsa.sign(key.curve, hash, msg, key.data);
    default:
      throw new Error('Unsupported algorithm.');
  }
};

exports._verifyAsync = co(function* verifyAsync(hash, msg, sig, key) {
  switch (key.alg) {
    case 'dsa':
      return yield pk.dsa.verifyAsync(hash, msg, sig, key.data, key.params);
    case 'rsa':
      return yield pk.rsa.verifyAsync(hash, msg, sig, key.data);
    case 'ecdsa':
      return yield pk.ecdsa.verifyAsync(key.curve, hash, msg, sig, key.data);
    default:
      throw new Error('Unsupported algorithm.');
  }
});

exports.verifyAsync = co(function* verifyAsync(hash, msg, sig, key) {
  try {
    return yield exports._verifyAsync(hash, msg, sig, key);
  } catch (e) {
    return false;
  }
});

exports.signAsync = co(function* signAsync(hash, msg, key) {
  switch (key.alg) {
    case 'dsa':
      return yield pk.dsa.signAsync(hash, msg, key.data, key.params);
    case 'rsa':
      return yield pk.rsa.signAsync(hash, msg, key.data);
    case 'ecdsa':
      return yield pk.ecdsa.signAsync(key.curve, hash, msg, key.data);
    default:
      throw new Error('Unsupported algorithm.');
  }
});
