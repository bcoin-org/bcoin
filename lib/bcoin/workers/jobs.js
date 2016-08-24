/*!
 * jobs.js - worker jobs for bcoin
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var bcoin = require('./env');

/**
 * Jobs to execute within the worker.
 * @memberof Workers
 * @const {Object}
 */

var jobs = exports;

/**
 * Execute tx.verify() on worker.
 * @see TX#verify
 * @param {TX} tx
 * @param {VerifyFlags} flags
 * @returns {Boolean}
 */

jobs.verify = function verify(tx, flags) {
  return tx.verify(flags);
};

/**
 * Execute Wallet.sign() on worker.
 * @see Wallet.sign
 * @param {KeyRing[]} rings
 * @param {HDPrivateKey} master
 * @param {MTX} tx
 */

jobs.sign = function sign(tx, ring, type) {
  var total = tx.sign(ring, type);
  var sigs = [];
  var i, input;

  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];
    sigs.push([input.script, input.witness]);
  }

  return [sigs, total];
};

/**
 * Mine a block on worker.
 * @param {Object} attempt - Naked {@link MinerBlock}.
 * @returns {Block}
 */

jobs.mine = function mine(attempt) {
  attempt.on('status', function(stat) {
    bcoin.master.sendEvent('status', stat);
  });
  return attempt.mineSync();
};

/**
 * Execute scrypt() on worker.
 * @see scrypt
 * @param {Buffer} passwd
 * @param {Buffer} salt
 * @param {Number} N
 * @param {Number} r
 * @param {Number} p
 * @param {Number} len
 * @returns {Buffer}
 */

jobs.scrypt = function scrypt(passwd, salt, N, r, p, len) {
  var scrypt = require('../crypto/scrypt');
  return scrypt(passwd, salt, N >>> 0, r >>> 0, p >>> 0, len);
};
