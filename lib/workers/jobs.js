/*!
 * jobs.js - worker jobs for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var ec = require('../crypto/ec');
var scrypt = require('../crypto/scrypt');
var mine = require('../mining/mine');
var packets = require('./packets');

/**
 * @exports workers/jobs
 */

var jobs = exports;

/**
 * Execute a job on the worker.
 * @param {String} cmd
 * @param {Array} args
 * @returns {Object}
 * @throws on unknown command
 */

jobs.execute = function execute(p) {
  try {
    return jobs._execute(p);
  } catch (e) {
    return new packets.ErrorResultPacket(e);
  }
};

/**
 * Execute a job on the worker.
 * @param {String} cmd
 * @param {Array} args
 * @returns {Object}
 * @throws on unknown command
 */

jobs._execute = function execute(p) {
  switch (p.cmd) {
    case packets.types.VERIFY:
      return jobs.verify(p.tx, p.view, p.flags);
    case packets.types.VERIFYINPUT:
      return jobs.verifyInput(p.tx, p.index, p.coin, p.flags);
    case packets.types.SIGN:
      return jobs.sign(p.tx, p.rings, p.type);
    case packets.types.SIGNINPUT:
      return jobs.signInput(p.tx, p.index, p.coin, p.ring, p.type);
    case packets.types.ECVERIFY:
      return jobs.ecVerify(p.msg, p.sig, p.key);
    case packets.types.ECSIGN:
      return jobs.ecSign(p.msg, p.key);
    case packets.types.MINE:
      return jobs.mine(p.data, p.target, p.min, p.max);
    case packets.types.SCRYPT:
      return jobs.scrypt(p.passwd, p.salt, p.N, p.r, p.p, p.len);
    default:
      throw new Error('Unknown command: "' + p.cmd + '".');
  }
};

/**
 * Execute tx.verify() on worker.
 * @see TX#verify
 * @param {TX} tx
 * @param {CoinView} view
 * @param {VerifyFlags} flags
 * @returns {Boolean}
 */

jobs.verify = function verify(tx, view, flags) {
  var result = tx.verify(view, flags);
  return new packets.VerifyResultPacket(result);
};

/**
 * Execute tx.verifyInput() on worker.
 * @see TX#verifyInput
 * @param {TX} tx
 * @param {Number} index
 * @param {Output} coin
 * @param {VerifyFlags} flags
 * @returns {Boolean}
 */

jobs.verifyInput = function verifyInput(tx, index, coin, flags) {
  var result = tx.verifyInput(index, coin, flags);
  return new packets.VerifyInputResultPacket(result);
};

/**
 * Execute tx.sign() on worker.
 * @see MTX#sign
 * @param {MTX} tx
 * @param {KeyRing[]} ring
 * @param {SighashType} type
 */

jobs.sign = function sign(tx, ring, type) {
  var total = tx.sign(ring, type);
  return packets.SignResultPacket.fromTX(tx, total);
};

/**
 * Execute tx.signInput() on worker.
 * @see MTX#signInput
 * @param {MTX} tx
 * @param {Number} index
 * @param {Output} coin
 * @param {KeyRing} ring
 * @param {SighashType} type
 */

jobs.signInput = function signInput(tx, index, coin, ring, type) {
  var result = tx.signInput(tx, index, coin, ring, type);
  return packets.SignInputResultPacket.fromTX(tx, index, result);
};

/**
 * Execute ec.verify() on worker.
 * @see ec.verify
 * @param {TX} tx
 * @param {VerifyFlags} flags
 * @returns {Boolean}
 */

jobs.ecVerify = function ecVerify(msg, sig, key) {
  var result = ec.verify(msg, sig, key);
  return new packets.ECVerifyResultPacket(result);
};

/**
 * Execute ec.sign() on worker.
 * @see ec.sign
 * @param {TX} tx
 * @param {Number} index
 * @param {VerifyFlags} flags
 * @returns {Boolean}
 */

jobs.ecSign = function ecSign(msg, key) {
  var sig = ec.sign(msg, key);
  return new packets.ECSignResultPacket(sig);
};

/**
 * Mine a block on worker.
 * @param {Buffer} data
 * @param {Buffer} target
 * @param {Number} min
 * @param {Number} max
 * @returns {Number}
 */

jobs.mine = function _mine(data, target, min, max) {
  var nonce = mine(data, target, min, max);
  return new packets.MineResultPacket(nonce);
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

jobs.scrypt = function _scrypt(passwd, salt, N, r, p, len) {
  var key = scrypt(passwd, salt, N, r, p, len);
  return new packets.ScryptResultPacket(key);
};
