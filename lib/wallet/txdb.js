/*!
 * txdb.js - persistent transaction pool
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var utils = require('../utils/utils');
var LRU = require('../utils/lru');
var co = require('../utils/co');
var assert = require('assert');
var constants = require('../protocol/constants');
var BufferReader = require('../utils/reader');
var BufferWriter = require('../utils/writer');
var TX = require('../primitives/tx');
var Coin = require('../primitives/coin');
var Outpoint = require('../primitives/outpoint');
var DUMMY = new Buffer([0]);

/*
 * Database Layout:
 *   t[hash] -> extended tx
 *   c[hash][index] -> coin
 *   d[hash][index] -> undo coin
 *   s[hash][index] -> spent by hash
 *   o[hash][index] -> orphan inputs
 *   p[hash] -> dummy (pending flag)
 *   m[time][hash] -> dummy (tx by time)
 *   h[height][hash] -> dummy (tx by height)
 *   T[account][hash] -> dummy (tx by account)
 *   P[account][hash] -> dummy (pending tx by account)
 *   M[account][time][hash] -> dummy (tx by time + account)
 *   H[account][height][hash] -> dummy (tx by height + account)
 *   C[account][hash][index] -> dummy (coin by account)
 *   r[hash] -> dummy (replace by fee chain)
 */

var layout = {
  prefix: function prefix(wid, key) {
    var out = new Buffer(5 + key.length);
    out[0] = 0x74;
    out.writeUInt32BE(wid, 1);
    key.copy(out, 5);
    return out;
  },
  pre: function prefix(key) {
    return key.readUInt32BE(1, true);
  },
  R: new Buffer([0x52]),
  hi: function hi(ch, hash, index) {
    var key = new Buffer(37);
    key[0] = ch;
    key.write(hash, 1, 'hex');
    key.writeUInt32BE(index, 33, true);
    return key;
  },
  hii: function hii(key) {
    key = key.slice(6);
    return [key.toString('hex', 0, 32), key.readUInt32BE(32, true)];
  },
  ih: function ih(ch, index, hash) {
    var key = new Buffer(37);
    key[0] = ch;
    key.writeUInt32BE(index, 1, true);
    key.write(hash, 5, 'hex');
    return key;
  },
  ihh: function ihh(key) {
    key = key.slice(6);
    return [key.readUInt32BE(0, true), key.toString('hex', 4, 36)];
  },
  iih: function iih(ch, index, num, hash) {
    var key = new Buffer(41);
    key[0] = ch;
    key.writeUInt32BE(index, 1, true);
    key.writeUInt32BE(num, 5, true);
    key.write(hash, 9, 'hex');
    return key;
  },
  iihh: function iihh(key) {
    key = key.slice(6);
    return [
      key.readUInt32BE(0, true),
      key.readUInt32BE(4, true),
      key.toString('hex', 8, 40)
    ];
  },
  ihi: function ihi(ch, index, hash, num) {
    var key = new Buffer(41);
    key[0] = ch;
    key.writeUInt32BE(index, 1, true);
    key.write(hash, 5, 'hex');
    key.writeUInt32BE(num, 37, true);
    return key;
  },
  ihii: function ihii(key) {
    key = key.slice(6);
    return [
      key.readUInt32BE(0, true),
      key.toString('hex', 4, 36),
      key.readUInt32BE(36, true)
    ];
  },
  ha: function ha(ch, hash) {
    var key = new Buffer(33);
    key[0] = ch;
    key.write(hash, 1, 'hex');
    return key;
  },
  haa: function haa(key) {
    key = key.slice(6);
    return key.toString('hex', 0);
  },
  t: function t(hash) {
    return layout.ha(0x74, hash);
  },
  tt: function tt(key) {
    return layout.haa(key);
  },
  c: function c(hash, index) {
    return layout.hi(0x63, hash, index);
  },
  cc: function cc(key) {
    return layout.hii(key);
  },
  d: function d(hash, index) {
    return layout.hi(0x64, hash, index);
  },
  dd: function dd(key) {
    return layout.hii(key);
  },
  s: function s(hash, index) {
    return layout.hi(0x73, hash, index);
  },
  ss: function ss(key) {
    return layout.hii(key);
  },
  p: function p(hash) {
    return layout.ha(0x70, hash);
  },
  pp: function pp(key) {
    return layout.haa(key);
  },
  m: function m(time, hash) {
    return layout.ih(0x6d, time, hash);
  },
  mm: function mm(key) {
    return layout.ihh(key);
  },
  h: function h(height, hash) {
    return layout.ih(0x68, height, hash);
  },
  hh: function hh(key) {
    return layout.ihh(key);
  },
  T: function T(account, hash) {
    return layout.ih(0x54, account, hash);
  },
  Tt: function Tt(key) {
    return layout.ihh(key);
  },
  P: function P(account, hash) {
    return layout.ih(0x50, account, hash);
  },
  Pp: function Pp(key) {
    return layout.ihh(key);
  },
  M: function M(account, time, hash) {
    return layout.iih(0x4d, account, time, hash);
  },
  Mm: function Mm(key) {
    return layout.iihh(key);
  },
  H: function H(account, height, hash) {
    return layout.iih(0x48, account, height, hash);
  },
  Hh: function Hh(key) {
    return layout.iihh(key);
  },
  C: function C(account, hash, index) {
    return layout.ihi(0x43, account, hash, index);
  },
  Cc: function Cc(key) {
    return layout.ihii(key);
  },
  r: function r(hash) {
    return layout.ha(0x72, hash);
  }
};

if (utils.isBrowser)
  layout = require('./browser').txdb;

/**
 * TXDB
 * @exports TXDB
 * @constructor
 * @param {Wallet} wallet
 */

function TXDB(wallet) {
  if (!(this instanceof TXDB))
    return new TXDB(wallet);

  this.wallet = wallet;
  this.walletdb = wallet.db;
  this.db = wallet.db.db;
  this.logger = wallet.db.logger;
  this.network = wallet.db.network;
  this.options = wallet.db.options;
  this.coinCache = new LRU(10000);

  this.locked = {};
  this.state = null;
  this.pending = null;
  this.events = [];

  this.orphans = {};
  this.count = {};
  this.totalOrphans = 0;
}

/**
 * Database layout.
 * @type {Object}
 */

TXDB.layout = layout;

/**
 * Open TXDB.
 * @returns {Promise}
 */

TXDB.prototype.open = co(function* open() {
  var state = yield this.getState();

  if (state) {
    this.state = state;
    this.logger.info('TXDB loaded for %s.', this.wallet.id);
  } else {
    this.state = new TXDBState(this.wallet.wid, this.wallet.id);
    this.logger.info('TXDB created for %s.', this.wallet.id);
  }

  this.logger.info('TXDB State: tx=%d coin=%s.',
    this.state.tx, this.state.coin);

  this.logger.info(
    'Balance: unconfirmed=%s confirmed=%s.',
    utils.btc(this.state.unconfirmed),
    utils.btc(this.state.confirmed));
});

/**
 * Start batch.
 * @private
 */

TXDB.prototype.start = function start() {
  this.pending = this.state.clone();
  return this.wallet.start();
};

/**
 * Drop batch.
 * @private
 */

TXDB.prototype.drop = function drop() {
  this.pending = null;
  this.events.length = 0;
  return this.wallet.drop();
};

/**
 * Clear batch.
 * @private
 */

TXDB.prototype.clear = function clear() {
  this.pending = this.state.clone();
  this.events.length = 0;
  return this.wallet.clear();
};

/**
 * Save batch.
 * @returns {Promise}
 */

TXDB.prototype.commit = co(function* commit() {
  var i, item;

  try {
    yield this.wallet.commit();
  } catch (e) {
    this.pending = null;
    this.events.length = 0;
    throw e;
  }

  // Overwrite the entire state
  // with our new committed state.
  if (this.pending.committed) {
    this.state = this.pending;

    // Emit buffered events now that
    // we know everything is written.
    for (i = 0; i < this.events.length; i++) {
      item = this.events[i];
      this.walletdb.emit(item[0], this.wallet.id, item[1], item[2]);
      this.wallet.emit(item[0], item[1], item[2]);
    }
  }

  this.pending = null;
  this.events.length = 0;
});

/**
 * Emit transaction event.
 * @private
 * @param {String} event
 * @param {Object} data
 * @param {Details} details
 */

TXDB.prototype.emit = function emit(event, data, details) {
  this.events.push([event, data, details]);
};

/**
 * Prefix a key.
 * @param {Buffer} key
 * @returns {Buffer} Prefixed key.
 */

TXDB.prototype.prefix = function prefix(key) {
  assert(this.wallet.wid);
  return layout.prefix(this.wallet.wid, key);
};

/**
 * Put key and value to current batch.
 * @param {String} key
 * @param {Buffer} value
 */

TXDB.prototype.put = function put(key, value) {
  assert(this.wallet.current);
  this.wallet.current.put(this.prefix(key), value);
};

/**
 * Delete key from current batch.
 * @param {String} key
 */

TXDB.prototype.del = function del(key) {
  assert(this.wallet.current);
  this.wallet.current.del(this.prefix(key));
};

/**
 * Get.
 * @param {String} key
 */

TXDB.prototype.get = function get(key) {
  return this.db.get(this.prefix(key));
};

/**
 * Has.
 * @param {String} key
 */

TXDB.prototype.has = function has(key) {
  return this.db.has(this.prefix(key));
};

/**
 * Iterate.
 * @param {Object} options
 * @returns {Promise}
 */

TXDB.prototype.range = function range(options) {
  if (options.gte)
    options.gte = this.prefix(options.gte);
  if (options.lte)
    options.lte = this.prefix(options.lte);
  return this.db.range(options);
};

/**
 * Iterate.
 * @param {Object} options
 * @returns {Promise}
 */

TXDB.prototype.keys = function keys(options) {
  if (options.gte)
    options.gte = this.prefix(options.gte);
  if (options.lte)
    options.lte = this.prefix(options.lte);
  return this.db.keys(options);
};

/**
 * Iterate.
 * @param {Object} options
 * @returns {Promise}
 */

TXDB.prototype.values = function values(options) {
  if (options.gte)
    options.gte = this.prefix(options.gte);
  if (options.lte)
    options.lte = this.prefix(options.lte);
  return this.db.values(options);
};

/**
 * Get wallet path for output.
 * @param {Output} output
 * @returns {Promise} - Returns {@link Path}.
 */

TXDB.prototype.getPath = function getPath(output) {
  if (!output)
    return Promise.resolve();
  return this.wallet.getPath(output.getAddress());
};

/**
 * Test whether path exists for output.
 * @param {Output} output
 * @returns {Promise} - Returns Boolean.
 */

TXDB.prototype.hasPath = function hasPath(output) {
  if (!output)
    return Promise.resolve();
  return this.wallet.hasPath(output.getAddress());
};

/**
 * Determine which transactions to add.
 * Attempt to resolve orphans (for SPV).
 * @param {TX} tx
 * @returns {Promise}
 */

TXDB.prototype.resolve = co(function* add(tx) {
  var hash, result;

  if (!this.options.resolution)
    return [tx];

  hash = tx.hash('hex');

  if (yield this.hasTX(hash))
    return [tx];

  result = yield this.verifyInputs(tx);

  if (!result)
    return [];

  return yield this.resolveOutputs(tx);
});

/**
 * Verify inputs and potentially add orphans.
 * Used in SPV mode.
 * @param {TX} tx
 * @returns {Promise}
 */

TXDB.prototype.verifyInputs = co(function* verifyInputs(tx) {
  var hash = tx.hash('hex');
  var hasOrphans = false;
  var orphans = [];
  var i, input, prevout;
  var key, coin, spent;

  if (tx.isCoinbase())
    return true;

  if (this.count[hash])
    return false;

  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];
    prevout = input.prevout;

    coin = yield this.getCoin(prevout.hash, prevout.index);

    if (coin) {
      if (this.options.verify && tx.height === -1) {
        input.coin = coin;
        if (!(yield tx.verifyInputAsync(i)))
          return false;
      }

      continue;
    }

    spent = yield this.getSpent(prevout.hash, prevout.index);

    if (spent) {
      coin = yield this.getSpentCoin(spent, prevout);

      if (!coin)
        continue;

      if (this.options.verify && tx.height === -1) {
        input.coin = coin;
        if (!(yield tx.verifyInputAsync(i)))
          return false;
      }

      continue;
    }

    if (yield this.hasPath(input))
      orphans[i] = true;
  }

  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];
    prevout = input.prevout;

    if (!orphans[i])
      continue;

    key = prevout.hash + prevout.index;

    if (this.totalOrphans > 20) {
      this.logger.warning('Potential orphan flood!');
      this.logger.warning(
        'More than 20 orphans for %s. Purging.',
        this.wallet.id);
      this.totalOrphans = 0;
      this.orphans = {};
      this.count = {};
    }

    if (!this.orphans[key])
      this.orphans[key] = [];

    if (!this.count[hash])
      this.count[hash] = 0;

    this.orphans[key].push(new Orphan(tx, i));
    this.count[hash]++;
    this.totalOrphans++;

    hasOrphans = true;
  }

  if (hasOrphans)
    return false;

  return true;
});

/**
 * Resolve orphans for outputs.
 * Used in SPV mode.
 * @param {TX} tx
 * @returns {Promise}
 */

TXDB.prototype.resolveOutputs = co(function* resolveOutputs(tx, resolved) {
  var hash = tx.hash('hex');
  var i, j, input, output, key;
  var orphans, orphan, coin, valid;

  if (!resolved)
    resolved = [];

  resolved.push(tx);

  for (i = 0; i < tx.outputs.length; i++) {
    output = tx.outputs[i];
    key = hash + i;
    orphans = this.orphans[key];

    if (!orphans)
      continue;

    delete this.orphans[key];

    coin = Coin.fromTX(tx, i);

    for (j = 0; j < orphans.length; j++) {
      orphan = orphans[j];
      valid = true;

      input = orphan.tx.inputs[orphan.index];

      assert(input.prevout.hash === hash);
      assert(input.prevout.index === i);

      if (this.options.verify && orphan.tx.height === -1) {
        input.coin = coin;
        valid = yield orphan.tx.verifyInputAsync(orphan.index);
      }

      if (valid) {
        if (--this.count[orphan.hash] === 0) {
          delete this.count[orphan.hash];
          yield this.resolveOutputs(orphan.tx, resolved);
        }
        break;
      }

      delete this.count[orphan.hash];
    }
  }

  return resolved;
});

/**
 * Save credit.
 * @param {Credit} credit
 * @param {Path} path
 */

TXDB.prototype.saveCredit = function saveCredit(credit, path) {
  var prevout = credit.coin;
  var key = prevout.hash + prevout.index;
  var raw = credit.toRaw();
  this.put(layout.c(prevout.hash, prevout.index), raw);
  this.put(layout.C(path.account, prevout.hash, prevout.index), DUMMY);
  this.coinCache.set(key, raw);
};

/**
 * Remove credit.
 * @param {Credit} credit
 * @param {Path} path
 */

TXDB.prototype.removeCredit = function removeCredit(credit, path) {
  var prevout = credit.coin;
  var key = prevout.hash + prevout.index;
  this.del(layout.c(prevout.hash, prevout.index));
  this.del(layout.C(path.account, prevout.hash, prevout.index));
  this.coinCache.remove(key);
};

/**
 * Spend credit.
 * @param {Credit} credit
 * @param {TX} tx
 * @param {Number} i
 */

TXDB.prototype.spendCredit = function spendCredit(credit, tx, i) {
  var prevout = tx.inputs[i].prevout;
  var spender = Outpoint.fromTX(tx, i);
  this.put(layout.s(prevout.hash, prevout.index), spender.toRaw());
  this.put(layout.d(spender.hash, spender.index), credit.coin.toRaw());
};

/**
 * Unspend credit.
 * @param {TX} tx
 * @param {Number} i
 */

TXDB.prototype.unspendCredit = function unspendCredit(tx, i) {
  var prevout = tx.inputs[i].prevout;
  var spender = Outpoint.fromTX(tx, i);
  this.del(layout.s(prevout.hash, prevout.index));
  this.del(layout.d(spender.hash, spender.index));
};

/**
 * Write input record.
 * @param {TX} tx
 * @param {Number} i
 */

TXDB.prototype.writeInput = function writeInput(tx, i) {
  var prevout = tx.inputs[i].prevout;
  var spender = Outpoint.fromTX(tx, i);
  this.put(layout.s(prevout.hash, prevout.index), spender.toRaw());
};

/**
 * Remove input record.
 * @param {TX} tx
 * @param {Number} i
 */

TXDB.prototype.removeInput = function removeInput(tx, i) {
  var prevout = tx.inputs[i].prevout;
  this.del(layout.s(prevout.hash, prevout.index));
};

/**
 * Resolve orphan input.
 * @param {TX} tx
 * @param {Number} i
 * @param {Path} path
 * @returns {Boolean}
 */

TXDB.prototype.resolveInput = co(function* resolveInput(tx, i, path) {
  var hash = tx.hash('hex');
  var spent = yield this.getSpent(hash, i);
  var stx, credit;

  if (!spent)
    return false;

  if (yield this.hasSpentCoin(spent))
    return false;

  stx = yield this.getTX(spent.hash);
  assert(stx);

  credit = Credit.fromTX(tx, i);

  this.spendCredit(credit, stx, spent.index);

  if (stx.height === -1) {
    credit.spent = true;
    this.saveCredit(credit, path);
    this.pending.coin++;
    if (tx.height !== -1)
      this.pending.confirmed += credit.coin.value;
  }

  return true;
});

/**
 * Test an entire transaction to see
 * if any of its outpoints are a double-spend.
 * @param {TX} tx
 * @returns {Promise} - Returns Boolean.
 */

TXDB.prototype.isDoubleSpend = co(function* isDoubleSpend(tx) {
  var i, input, prevout, spent;

  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];
    prevout = input.prevout;
    spent = yield this.isSpent(prevout.hash, prevout.index);
    if (spent)
      return true;
  }

  return false;
});

/**
 * Test an entire transaction to see
 * if any of its outpoints are replace by fee.
 * @param {TX} tx
 * @returns {Promise} - Returns Boolean.
 */

TXDB.prototype.isRBF = co(function* isRBF(tx) {
  var i, input, prevout;

  if (tx.isRBF())
    return true;

  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];
    prevout = input.prevout;
    if (yield this.has(layout.r(prevout.hash)))
      return true;
  }

  return false;
});

/**
 * Test a whether a coin has been spent.
 * @param {Hash} hash
 * @param {Number} index
 * @returns {Promise} - Returns Boolean.
 */

TXDB.prototype.getSpent = co(function* getSpent(hash, index) {
  var data = yield this.get(layout.s(hash, index));

  if (!data)
    return;

  return Outpoint.fromRaw(data);
});

/**
 * Test a whether a coin has been spent.
 * @param {Hash} hash
 * @param {Number} index
 * @returns {Promise} - Returns Boolean.
 */

TXDB.prototype.isSpent = co(function* isSpent(hash, index) {
  var data = yield this.get(layout.s(hash, index));
  return data != null;
});

/**
 * Add transaction, runs `confirm()` and `verify()`.
 * @param {TX} tx
 * @returns {Promise}
 */

TXDB.prototype.add = co(function* add(tx) {
  var result;

  this.start();

  try {
    result = yield this._add(tx);
  } catch (e) {
    this.drop();
    throw e;
  }

  yield this.commit();

  return result;
});

/**
 * Add transaction without a lock.
 * @private
 * @param {TX} tx
 * @returns {Promise}
 */

TXDB.prototype._add = co(function* add(tx) {
  var hash = tx.hash('hex');
  var existing = yield this.getTX(hash);

  assert(!tx.mutable, 'Cannot add mutable TX to wallet.');

  if (existing) {
    // Existing tx is already confirmed. Ignore.
    if (existing.height !== -1)
      return;

    // The incoming tx won't confirm the
    // existing one anyway. Ignore.
    if (tx.height === -1)
      return;

    // Save the original time.
    tx.ps = existing.ps;

    // Attempt to confirm tx before adding it.
    return yield this.confirm(tx);
  }

  if (tx.height === -1) {
    // We ignore double spends from the mempool.
    if (yield this.isDoubleSpend(tx))
      return;

    // We ignore any unconfirmed txs
    // that are replace-by-fee.
    if (yield this.isRBF(tx)) {
      this.put(layout.r(hash), DUMMY);
      return;
    }
  } else {
    // Potentially remove double-spenders.
    yield this.removeConflicts(tx);

    // Delete the replace-by-fee record.
    this.del(layout.r(hash));
  }

  return yield this._insert(tx);
});

/**
 * Add transaction without a lock.
 * @private
 * @param {TX} tx
 * @returns {Promise}
 */

TXDB.prototype._insert = co(function* insert(tx) {
  var hash = tx.hash('hex');
  var details = new Details(this, tx);
  var i, input, output, coin;
  var prevout, credit, path, account;

  if (!tx.isCoinbase()) {
    for (i = 0; i < tx.inputs.length; i++) {
      input = tx.inputs[i];
      prevout = input.prevout;
      credit = yield this.getCredit(prevout.hash, prevout.index);

      if (!credit) {
        this.writeInput(tx, i);
        continue;
      }

      coin = credit.coin;
      path = yield this.getPath(coin);
      assert(path);

      details.setInput(i, path, coin);

      this.spendCredit(credit, tx, i);

      this.pending.unconfirmed -= coin.value;

      if (tx.height === -1) {
        credit.spent = true;
        this.saveCredit(credit, path);
      } else {
        this.pending.coin--;
        this.pending.confirmed -= coin.value;
        this.removeCredit(credit, path);
      }
    }
  }

  for (i = 0; i < tx.outputs.length; i++) {
    output = tx.outputs[i];
    path = yield this.getPath(output);

    if (!path)
      continue;

    details.setOutput(i, path);

    if (yield this.resolveInput(tx, i, path))
      continue;

    credit = Credit.fromTX(tx, i);

    this.pending.coin++;
    this.pending.unconfirmed += output.value;

    if (tx.height !== -1)
      this.pending.confirmed += output.value;

    this.saveCredit(credit, path);
  }

  this.put(layout.t(hash), tx.toExtended());
  this.put(layout.m(tx.ps, hash), DUMMY);

  if (tx.height === -1)
    this.put(layout.p(hash), DUMMY);
  else
    this.put(layout.h(tx.height, hash), DUMMY);

  for (i = 0; i < details.accounts.length; i++) {
    account = details.accounts[i];

    this.put(layout.T(account, hash), DUMMY);
    this.put(layout.M(account, tx.ps, hash), DUMMY);

    if (tx.height === -1)
      this.put(layout.P(account, hash), DUMMY);
    else
      this.put(layout.H(account, tx.height, hash), DUMMY);
  }

  this.pending.tx++;
  this.put(layout.R, this.pending.commit());

  this.unlockTX(tx);

  this.emit('tx', tx, details);

  if (tx.height !== -1)
    this.emit('confirmed', tx, details);

  this.emit('balance', this.pending.toBalance(), details);

  return details;
});

/**
 * Attempt to confirm a transaction.
 * @private
 * @param {TX} tx
 * @returns {Promise} - Returns Boolean. `false` if
 * the transaction should be added to the database, `true` if the
 * transaction was confirmed, or should be ignored.
 */

TXDB.prototype.confirm = co(function* confirm(tx) {
  var hash = tx.hash('hex');
  var details = new Details(this, tx);
  var i, account, output, coin, input, prevout;
  var path, credit, credits;

  if (!tx.isCoinbase()) {
    credits = yield this.getSpentCredits(tx);

    for (i = 0; i < tx.inputs.length; i++) {
      input = tx.inputs[i];
      prevout = input.prevout;
      credit = credits[i];

      // There may be new credits available
      // that we haven't seen yet.
      if (!credit) {
        credit = yield this.getCredit(prevout.hash, prevout.index);

        if (!credit)
          continue;

        this.spendCredit(credit, tx, i);

        this.pending.unconfirmed -= credit.coin.value;
      }

      coin = credit.coin;

      assert(coin.height !== -1);

      path = yield this.getPath(coin);
      assert(path);

      details.setInput(i, path, coin);

      this.pending.coin--;
      this.pending.confirmed -= coin.value;

      this.removeCredit(credit, path);
    }
  }

  for (i = 0; i < tx.outputs.length; i++) {
    output = tx.outputs[i];
    path = yield this.getPath(output);

    if (!path)
      continue;

    details.setOutput(i, path);

    if (yield this.resolveInput(tx, i, path))
      continue;

    credit = yield this.getCredit(hash, i);
    assert(credit);

    if (credit.spent)
      yield this.updateSpentCoin(tx, i);

    coin = credit.coin;
    coin.height = tx.height;

    this.pending.coin++;
    this.pending.confirmed += output.value;

    this.saveCredit(credit, path);
  }

  this.put(layout.t(hash), tx.toExtended());
  this.del(layout.p(hash));
  this.put(layout.h(tx.height, hash), DUMMY);

  for (i = 0; i < details.accounts.length; i++) {
    account = details.accounts[i];
    this.del(layout.P(account, hash));
    this.put(layout.H(account, tx.height, hash), DUMMY);
  }

  this.put(layout.R, this.pending.commit());

  this.unlockTX(tx);

  this.emit('tx', tx, details);
  this.emit('confirmed', tx, details);
  this.emit('balance', this.pending.toBalance(), details);

  return details;
});

/**
 * Remove a transaction from the database. Disconnect inputs.
 * @param {Hash} hash
 * @returns {Promise}
 */

TXDB.prototype.remove = co(function* remove(hash) {
  var tx = yield this.getTX(hash);
  var details;

  if (!tx)
    return;

  details = yield this.removeRecursive(tx);

  if (!details)
    return;

  return details;
});

/**
 * Remove a transaction and recursively
 * remove all of its spenders.
 * @private
 * @param {TX} tx - Transaction to be removed.
 * @returns {Promise} - Returns Boolean.
 */

TXDB.prototype.removeRecursive = co(function* removeRecursive(tx) {
  var hash = tx.hash('hex');
  var i, spent, stx, details;

  for (i = 0; i < tx.outputs.length; i++) {
    spent = yield this.getSpent(hash, i);

    if (!spent)
      continue;

    // Remove all of the spender's spenders first.
    stx = yield this.getTX(spent.hash);

    assert(stx);

    yield this.removeRecursive(stx);
  }

  this.start();

  // Remove the spender.
  details = yield this._remove(tx);

  assert(details);

  yield this.commit();

  return details;
});

/**
 * Remove a transaction from the database. Disconnect inputs.
 * @private
 * @param {TX} tx
 * @returns {Promise}
 */

TXDB.prototype._remove = co(function* remove(tx) {
  var hash = tx.hash('hex');
  var details = new Details(this, tx);
  var i, path, account, credits;
  var input, output, coin, credit;

  if (!tx.isCoinbase()) {
    credits = yield this.getSpentCredits(tx);

    for (i = 0; i < tx.inputs.length; i++) {
      input = tx.inputs[i];
      credit = credits[i];

      if (!credit) {
        this.removeInput(tx, i);
        continue;
      }

      coin = credit.coin;
      path = yield this.getPath(coin);
      assert(path);

      details.setInput(i, path, coin);

      this.pending.unconfirmed += coin.value;

      if (tx.height !== -1) {
        this.pending.coin++;
        this.pending.confirmed += coin.value;
      }

      this.unspendCredit(tx, i);
      this.saveCredit(credit, path);
    }
  }

  for (i = 0; i < tx.outputs.length; i++) {
    output = tx.outputs[i];
    path = yield this.getPath(output);

    if (!path)
      continue;

    details.setOutput(i, path);

    credit = Credit.fromTX(tx, i);

    this.pending.coin--;
    this.pending.unconfirmed -= output.value;

    if (tx.height !== -1)
      this.pending.confirmed -= output.value;

    this.removeCredit(credit, path);
  }

  this.del(layout.t(hash));
  this.del(layout.m(tx.ps, hash));

  if (tx.height === -1)
    this.del(layout.p(hash));
  else
    this.del(layout.h(tx.height, hash));

  for (i = 0; i < details.accounts.length; i++) {
    account = details.accounts[i];

    this.del(layout.T(account, hash));
    this.del(layout.M(account, tx.ps, hash));

    if (tx.height === -1)
      this.del(layout.P(account, hash));
    else
      this.del(layout.H(account, tx.height, hash));
  }

  this.pending.tx--;
  this.put(layout.R, this.pending.commit());

  this.emit('remove tx', tx, details);
  this.emit('balance', this.pending.toBalance(), details);

  return details;
});

/**
 * Unconfirm a transaction. This is usually necessary after a reorg.
 * @param {Hash} hash
 * @returns {Promise}
 */

TXDB.prototype.unconfirm = co(function* unconfirm(hash) {
  var details;

  this.start();

  try {
    details = yield this._unconfirm(hash);
  } catch (e) {
    this.drop();
    throw e;
  }

  yield this.commit();

  return details;
});

/**
 * Unconfirm a transaction without a lock.
 * @private
 * @param {Hash} hash
 * @returns {Promise}
 */

TXDB.prototype._unconfirm = co(function* unconfirm(hash) {
  var tx = yield this.getTX(hash);

  if (!tx)
    return;

  return yield this.__unconfirm(tx);
});

/**
 * Unconfirm a transaction. This is usually necessary after a reorg.
 * @param {Hash} hash
 * @returns {Promise}
 */

TXDB.prototype.__unconfirm = co(function* unconfirm(tx) {
  var hash = tx.hash('hex');
  var details = new Details(this, tx);
  var height = tx.height;
  var i, account, output, coin, credits;
  var input, path, credit;

  assert(height !== -1);

  tx.unsetBlock();

  if (!tx.isCoinbase()) {
    credits = yield this.getSpentCredits(tx);

    for (i = 0; i < tx.inputs.length; i++) {
      input = tx.inputs[i];
      credit = credits[i];

      if (!credit)
        continue;

      coin = credit.coin;

      assert(coin.height !== -1);

      path = yield this.getPath(coin);
      assert(path);

      details.setInput(i, path, coin);

      this.pending.coin++;
      this.pending.confirmed += coin.value;

      credit.spent = true;

      this.saveCredit(credit, path);
    }
  }

  for (i = 0; i < tx.outputs.length; i++) {
    output = tx.outputs[i];
    path = yield this.getPath(output);

    if (!path)
      continue;

    credit = yield this.getCredit(hash, i);

    if (!credit) {
      yield this.updateSpentCoin(tx, i);
      continue;
    }

    if (credit.spent)
      yield this.updateSpentCoin(tx, i);

    details.setOutput(i, path);

    coin = credit.coin;
    coin.height = -1;

    this.pending.coin++;
    this.pending.confirmed -= output.value;

    this.saveCredit(credit, path);
  }

  this.put(layout.t(hash), tx.toExtended());
  this.put(layout.p(hash), DUMMY);
  this.del(layout.h(height, hash));

  for (i = 0; i < details.accounts.length; i++) {
    account = details.accounts[i];
    this.put(layout.P(account, hash), DUMMY);
    this.del(layout.H(account, height, hash));
  }

  this.put(layout.R, this.pending.commit());

  this.emit('unconfirmed', tx, details);
  this.emit('balance', this.pending.toBalance(), details);

  return details;
});

/**
 * Remove spenders that have not been confirmed. We do this in the
 * odd case of stuck transactions or when a coin is double-spent
 * by a newer transaction. All previously-spending transactions
 * of that coin that are _not_ confirmed will be removed from
 * the database.
 * @private
 * @param {Hash} hash
 * @param {TX} ref - Reference tx, the tx that double-spent.
 * @returns {Promise} - Returns Boolean.
 */

TXDB.prototype.removeConflict = co(function* removeConflict(hash, ref) {
  var tx = yield this.getTX(hash);
  var details;

  assert(tx);

  this.logger.warning('Handling conflicting tx: %s.', utils.revHex(hash));

  this.drop();

  details = yield this.removeRecursive(tx);

  this.start();

  this.logger.warning('Removed conflict: %s.', tx.rhash);

  // Emit the _removed_ transaction.
  this.emit('conflict', tx, details);

  return details;
});

/**
 * Retrieve coins for own inputs, remove
 * double spenders, and verify inputs.
 * @private
 * @param {TX} tx
 * @returns {Promise}
 */

TXDB.prototype.removeConflicts = co(function* removeConflicts(tx) {
  var hash = tx.hash('hex');
  var i, input, prevout, spent;

  if (tx.isCoinbase())
    return;

  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];
    prevout = input.prevout;

    // Is it already spent?
    spent = yield this.getSpent(prevout.hash, prevout.index);

    if (!spent)
      continue;

    // Did _we_ spend it?
    if (spent.hash === hash)
      continue;

    // Remove the double spender.
    yield this.removeConflict(spent.hash, tx);
  }
});

/**
 * Lock all coins in a transaction.
 * @param {TX} tx
 */

TXDB.prototype.lockTX = function lockTX(tx) {
  var i, input;

  if (tx.isCoinbase())
    return;

  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];
    this.lockCoin(input.prevout);
  }
};

/**
 * Unlock all coins in a transaction.
 * @param {TX} tx
 */

TXDB.prototype.unlockTX = function unlockTX(tx) {
  var i, input;

  if (tx.isCoinbase())
    return;

  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];
    this.unlockCoin(input.prevout);
  }
};

/**
 * Lock a single coin.
 * @param {Coin|Outpoint} coin
 */

TXDB.prototype.lockCoin = function lockCoin(coin) {
  var key = coin.hash + coin.index;
  this.locked[key] = true;
};

/**
 * Unlock a single coin.
 * @param {Coin|Outpoint} coin
 */

TXDB.prototype.unlockCoin = function unlockCoin(coin) {
  var key = coin.hash + coin.index;
  delete this.locked[key];
};

/**
 * Test locked status of a single coin.
 * @param {Coin|Outpoint} coin
 */

TXDB.prototype.isLocked = function isLocked(coin) {
  var key = coin.hash + coin.index;
  return this.locked[key] === true;
};

/**
 * Filter array of coins or outpoints
 * for only unlocked ones.
 * @param {Coin[]|Outpoint[]}
 * @returns {Array}
 */

TXDB.prototype.filterLocked = function filterLocked(coins) {
  var out = [];
  var i, coin;

  for (i = 0; i < coins.length; i++) {
    coin = coins[i];
    if (!this.isLocked(coin))
      out.push(coin);
  }

  return out;
};

/**
 * Return an array of all locked outpoints.
 * @returns {Outpoint[]}
 */

TXDB.prototype.getLocked = function getLocked() {
  var keys = Object.keys(this.locked);
  var outpoints = [];
  var i, key, hash, index, outpoint;

  for (i = 0; i < keys.length; i++) {
    key = keys[i];
    hash = key.slice(0, 64);
    index = +key.slice(64);
    outpoint = new Outpoint(hash, index);
    outpoints.push(outpoint);
  }

  return outpoints;
};

/**
 * Get hashes of all transactions in the database.
 * @param {Number?} account
 * @returns {Promise} - Returns {@link Hash}[].
 */

TXDB.prototype.getAccountHistoryHashes = function getHistoryHashes(account) {
  return this.keys({
    gte: layout.T(account, constants.NULL_HASH),
    lte: layout.T(account, constants.HIGH_HASH),
    parse: function(key) {
      key = layout.Tt(key);
      return key[1];
    }
  });
};

/**
 * Get hashes of all transactions in the database.
 * @param {Number?} account
 * @returns {Promise} - Returns {@link Hash}[].
 */

TXDB.prototype.getHistoryHashes = function getHistoryHashes(account) {
  if (account != null)
    return this.getAccountHistoryHashes(account);

  return this.keys({
    gte: layout.t(constants.NULL_HASH),
    lte: layout.t(constants.HIGH_HASH),
    parse: layout.tt
  });
};

/**
 * Get hashes of all unconfirmed transactions in the database.
 * @param {Number?} account
 * @returns {Promise} - Returns {@link Hash}[].
 */

TXDB.prototype.getAccountPendingHashes = function getAccountPendingHashes(account) {
  return this.keys({
    gte: layout.P(account, constants.NULL_HASH),
    lte: layout.P(account, constants.HIGH_HASH),
    parse: function(key) {
      key = layout.Pp(key);
      return key[1];
    }
  });
};

/**
 * Get hashes of all unconfirmed transactions in the database.
 * @param {Number?} account
 * @returns {Promise} - Returns {@link Hash}[].
 */

TXDB.prototype.getPendingHashes = function getPendingHashes(account) {
  if (account != null)
    return this.getAccountPendingHashes(account);

  return this.keys({
    gte: layout.p(constants.NULL_HASH),
    lte: layout.p(constants.HIGH_HASH),
    parse: layout.pp
  });
};

/**
 * Get all coin hashes in the database.
 * @param {Number?} account
 * @returns {Promise} - Returns {@link Hash}[].
 */

TXDB.prototype.getAccountOutpoints = function getAccountOutpoints(account) {
  return this.keys({
    gte: layout.C(account, constants.NULL_HASH, 0),
    lte: layout.C(account, constants.HIGH_HASH, 0xffffffff),
    parse: function(key) {
      key = layout.Cc(key);
      return new Outpoint(key[1], key[2]);
    }
  });
};

/**
 * Get all coin hashes in the database.
 * @param {Number?} account
 * @returns {Promise} - Returns {@link Hash}[].
 */

TXDB.prototype.getOutpoints = function getOutpoints(account) {
  if (account != null)
    return this.getAccountOutpoints(account);

  return this.keys({
    gte: layout.c(constants.NULL_HASH, 0),
    lte: layout.c(constants.HIGH_HASH, 0xffffffff),
    parse: function(key) {
      key = layout.cc(key);
      return new Outpoint(key[0], key[1]);
    }
  });
};

/**
 * Get TX hashes by height range.
 * @param {Number?} account
 * @param {Object} options
 * @param {Number} options.start - Start height.
 * @param {Number} options.end - End height.
 * @param {Number?} options.limit - Max number of records.
 * @param {Boolean?} options.reverse - Reverse order.
 * @returns {Promise} - Returns {@link Hash}[].
 */

TXDB.prototype.getAccountHeightRangeHashes = function getAccountHeightRangeHashes(account, options) {
  var start = options.start || 0;
  var end = options.end || 0xffffffff;

  return this.keys({
    gte: layout.H(account, start, constants.NULL_HASH),
    lte: layout.H(account, end, constants.HIGH_HASH),
    limit: options.limit,
    reverse: options.reverse,
    parse: function(key) {
      key = layout.Hh(key);
      return key[2];
    }
  });
};

/**
 * Get TX hashes by height range.
 * @param {Number?} account
 * @param {Object} options
 * @param {Number} options.start - Start height.
 * @param {Number} options.end - End height.
 * @param {Number?} options.limit - Max number of records.
 * @param {Boolean?} options.reverse - Reverse order.
 * @returns {Promise} - Returns {@link Hash}[].
 */

TXDB.prototype.getHeightRangeHashes = function getHeightRangeHashes(account, options) {
  var start, end;

  if (account && typeof account === 'object') {
    options = account;
    account = null;
  }

  if (account != null)
    return this.getAccountHeightRangeHashes(account, options);

  start = options.start || 0;
  end = options.end || 0xffffffff;

  return this.keys({
    gte: layout.h(start, constants.NULL_HASH),
    lte: layout.h(end, constants.HIGH_HASH),
    limit: options.limit,
    reverse: options.reverse,
    parse: function(key) {
      key = layout.hh(key);
      return key[1];
    }
  });
};

/**
 * Get TX hashes by height.
 * @param {Number} height
 * @returns {Promise} - Returns {@link Hash}[].
 */

TXDB.prototype.getHeightHashes = function getHeightHashes(height) {
  return this.getHeightRangeHashes({ start: height, end: height });
};

/**
 * Get TX hashes by timestamp range.
 * @param {Number?} account
 * @param {Object} options
 * @param {Number} options.start - Start height.
 * @param {Number} options.end - End height.
 * @param {Number?} options.limit - Max number of records.
 * @param {Boolean?} options.reverse - Reverse order.
 * @returns {Promise} - Returns {@link Hash}[].
 */

TXDB.prototype.getAccountRangeHashes = function getAccountRangeHashes(account, options) {
  var start = options.start || 0;
  var end = options.end || 0xffffffff;

  return this.keys({
    gte: layout.M(account, start, constants.NULL_HASH),
    lte: layout.M(account, end, constants.HIGH_HASH),
    limit: options.limit,
    reverse: options.reverse,
    parse: function(key) {
      key = layout.Mm(key);
      return key[2];
    }
  });
};

/**
 * Get TX hashes by timestamp range.
 * @param {Number?} account
 * @param {Object} options
 * @param {Number} options.start - Start height.
 * @param {Number} options.end - End height.
 * @param {Number?} options.limit - Max number of records.
 * @param {Boolean?} options.reverse - Reverse order.
 * @returns {Promise} - Returns {@link Hash}[].
 */

TXDB.prototype.getRangeHashes = function getRangeHashes(account, options) {
  var start, end;

  if (account && typeof account === 'object') {
    options = account;
    account = null;
  }

  if (account != null)
    return this.getAccountRangeHashes(account, options);

  start = options.start || 0;
  end = options.end || 0xffffffff;

  return this.keys({
    gte: layout.m(start, constants.NULL_HASH),
    lte: layout.m(end, constants.HIGH_HASH),
    limit: options.limit,
    reverse: options.reverse,
    parse: function(key) {
      key = layout.mm(key);
      return key[1];
    }
  });
};

/**
 * Get transactions by timestamp range.
 * @param {Number?} account
 * @param {Object} options
 * @param {Number} options.start - Start time.
 * @param {Number} options.end - End time.
 * @param {Number?} options.limit - Max number of records.
 * @param {Boolean?} options.reverse - Reverse order.
 * @returns {Promise} - Returns {@link TX}[].
 */

TXDB.prototype.getRange = co(function* getRange(account, options) {
  var txs = [];
  var i, hashes, hash, tx;

  if (account && typeof account === 'object') {
    options = account;
    account = null;
  }

  hashes = yield this.getRangeHashes(account, options);

  for (i = 0; i < hashes.length; i++) {
    hash = hashes[i];
    tx = yield this.getTX(hash);

    if (!tx)
      continue;

    txs.push(tx);
  }

  return txs;
});

/**
 * Get last N transactions.
 * @param {Number?} account
 * @param {Number} limit - Max number of transactions.
 * @returns {Promise} - Returns {@link TX}[].
 */

TXDB.prototype.getLast = function getLast(account, limit) {
  return this.getRange(account, {
    start: 0,
    end: 0xffffffff,
    reverse: true,
    limit: limit || 10
  });
};

/**
 * Get all transactions.
 * @param {Number?} account
 * @returns {Promise} - Returns {@link TX}[].
 */

TXDB.prototype.getHistory = function getHistory(account) {
  // Slow case
  if (account != null)
    return this.getAccountHistory(account);

  // Fast case
  return this.values({
    gte: layout.t(constants.NULL_HASH),
    lte: layout.t(constants.HIGH_HASH),
    parse: TX.fromExtended
  });
};

/**
 * Get all account transactions.
 * @param {Number?} account
 * @returns {Promise} - Returns {@link TX}[].
 */

TXDB.prototype.getAccountHistory = co(function* getAccountHistory(account) {
  var hashes = yield this.getHistoryHashes(account);
  var txs = [];
  var i, hash, tx;

  for (i = 0; i < hashes.length; i++) {
    hash = hashes[i];
    tx = yield this.getTX(hash);

    if (!tx)
      continue;

    txs.push(tx);
  }

  return txs;
});

/**
 * Get unconfirmed transactions.
 * @param {Number?} account
 * @returns {Promise} - Returns {@link TX}[].
 */

TXDB.prototype.getPending = co(function* getPending(account) {
  var hashes = yield this.getPendingHashes(account);
  var txs = [];
  var i, hash, tx;

  for (i = 0; i < hashes.length; i++) {
    hash = hashes[i];
    tx = yield this.getTX(hash);

    if (!tx)
      continue;

    txs.push(tx);
  }

  return txs;
});

/**
 * Get coins.
 * @param {Number?} account
 * @returns {Promise} - Returns {@link Coin}[].
 */

TXDB.prototype.getCoins = co(function* getCoins(account, all) {
  var credits = yield this.getCredits(account, all);
  var coins = [];
  var i, credit;

  for (i = 0; i < credits.length; i++) {
    credit = credits[i];
    coins.push(credit.coin);
  }

  return coins;
});

/**
 * Get coins.
 * @param {Number?} account
 * @returns {Promise} - Returns {@link Coin}[].
 */

TXDB.prototype.getCredits = co(function* getCredits(account, all) {
  var self = this;
  var unspent = [];
  var i, credits, credit;

  // Slow case
  if (account != null)
    return this.getAccountCredits(account, all);

  // Fast case
  credits = yield this.range({
    gte: layout.c(constants.NULL_HASH, 0x00000000),
    lte: layout.c(constants.HIGH_HASH, 0xffffffff),
    parse: function(key, value) {
      var parts = layout.cc(key);
      var hash = parts[0];
      var index = parts[1];
      var credit = Credit.fromRaw(value);
      var ckey = hash + index;
      credit.coin.hash = hash;
      credit.coin.index = index;
      self.coinCache.set(ckey, value);
      return credit;
    }
  });

  if (all)
    return credits;

  for (i = 0; i < credits.length; i++) {
    credit = credits[i];
    if (credit.spent)
      continue;
    unspent.push(credit);
  }

  return unspent;
});

/**
 * Get coins by account.
 * @param {Number} account
 * @returns {Promise} - Returns {@link Coin}[].
 */

TXDB.prototype.getAccountCoins = co(function* getAccountCoins(account, all) {
  var credits = yield this.getAccountCredits(account, all);
  var coins = [];
  var i, credit;

  for (i = 0; i < credits.length; i++) {
    credit = credits[i];
    coins.push(credit.coin);
  }

  return coins;
});

/**
 * Get coins by account.
 * @param {Number} account
 * @returns {Promise} - Returns {@link Coin}[].
 */

TXDB.prototype.getAccountCredits = co(function* getAccountCredits(account, all) {
  var prevout = yield this.getOutpoints(account);
  var credits = [];
  var i, op, credit;

  for (i = 0; i < prevout.length; i++) {
    op = prevout[i];
    credit = yield this.getCredit(op.hash, op.index);

    if (!credit)
      continue;

    if (!all) {
      if (credit.spent)
        continue;
    }

    credits.push(credit);
  }

  return credits;
});

/**
 * Fill a transaction with coins (all historical coins).
 * @param {TX} tx
 * @returns {Promise} - Returns {@link TX}.
 */

TXDB.prototype.fillHistory = co(function* fillHistory(tx) {
  var i, input, credits, credit;

  if (tx.isCoinbase())
    return tx;

  credits = yield this.getSpentCredits(tx);

  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];
    credit = credits[i];

    if (!credit)
      continue;

    input.coin = credit.coin;
  }

  return tx;
});

/**
 * Fill a transaction with coins (all historical coins).
 * @param {TX} tx
 * @returns {Promise} - Returns {@link TX}.
 */

TXDB.prototype.getSpentCredits = co(function* getSpentCredits(tx) {
  var credits = [];
  var i, hash;

  for (i = 0; i < tx.inputs.length; i++)
    credits.push(null);

  if (tx.isCoinbase())
    return credits;

  hash = tx.hash('hex');

  yield this.range({
    gte: layout.d(hash, 0x00000000),
    lte: layout.d(hash, 0xffffffff),
    parse: function(key, value) {
      var index = layout.dd(key)[1];
      var coin = Coin.fromRaw(value);
      var input = tx.inputs[index];
      assert(input);
      coin.hash = input.prevout.hash;
      coin.index = input.prevout.index;
      credits[index] = new Credit(coin);
    }
  });

  return credits;
});

/**
 * Fill a transaction with coins.
 * @param {TX} tx
 * @returns {Promise} - Returns {@link TX}.
 */

TXDB.prototype.fillCoins = co(function* fillCoins(tx) {
  var i, input, prevout, credit;

  if (tx.isCoinbase())
    return tx;

  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];
    prevout = input.prevout;

    if (input.coin)
      continue;

    credit = yield this.getCredit(prevout.hash, prevout.index);

    if (!credit)
      continue;

    if (credit.spent)
      continue;

    input.coin = credit.coin;
  }

  return tx;
});

/**
 * Get TXDB state.
 * @returns {Promise}
 */

TXDB.prototype.getState = co(function* getState() {
  var data = yield this.get(layout.R);

  if (!data)
    return;

  return TXDBState.fromRaw(this.wallet.wid, this.wallet.id, data);
});

/**
 * Get transaction.
 * @param {Hash} hash
 * @returns {Promise} - Returns {@link TX}.
 */

TXDB.prototype.getTX = co(function* getTX(hash) {
  var tx = yield this.get(layout.t(hash));

  if (!tx)
    return;

  return TX.fromExtended(tx);
});

/**
 * Get transaction details.
 * @param {Hash} hash
 * @returns {Promise} - Returns {@link TXDetails}.
 */

TXDB.prototype.getDetails = co(function* getDetails(hash) {
  var tx = yield this.getTX(hash);

  if (!tx)
    return;

  return yield this.toDetails(tx);
});

/**
 * Convert transaction to transaction details.
 * @param {TX|TX[]} tx
 * @returns {Promise}
 */

TXDB.prototype.toDetails = co(function* toDetails(tx) {
  var i, out, txs, details;
  var coins, coin, path, output;

  if (Array.isArray(tx)) {
    out = [];
    txs = tx;

    for (i = 0; i < txs.length; i++) {
      tx = txs[i];
      details = yield this.toDetails(tx);

      if (!details)
        continue;

      out.push(details);
    }

    return out;
  }

  details = new Details(this, tx);

  coins = yield this.fillHistory(tx);

  for (i = 0; i < tx.inputs.length; i++) {
    coin = coins[i];
    path = yield this.getPath(coin);
    details.setInput(i, path, coin);
  }

  for (i = 0; i < tx.outputs.length; i++) {
    output = tx.outputs[i];
    path = yield this.getPath(output);
    details.setOutput(i, path);
  }

  return details;
});

/**
 * Test whether the database has a transaction.
 * @param {Hash} hash
 * @returns {Promise} - Returns Boolean.
 */

TXDB.prototype.hasTX = function hasTX(hash) {
  return this.has(layout.t(hash));
};

/**
 * Get coin.
 * @param {Hash} hash
 * @param {Number} index
 * @returns {Promise} - Returns {@link Coin}.
 */

TXDB.prototype.getCoin = co(function* getCoin(hash, index) {
  var credit = yield this.getCredit(hash, index);
  if (!credit)
    return;
  return credit.coin;
});

/**
 * Get coin.
 * @param {Hash} hash
 * @param {Number} index
 * @returns {Promise} - Returns {@link Coin}.
 */

TXDB.prototype.getCredit = co(function* getCredit(hash, index) {
  var key = hash + index;
  var data = this.coinCache.get(key);
  var credit;

  if (data) {
    credit = Credit.fromRaw(data);
    credit.coin.hash = hash;
    credit.coin.index = index;
    return credit;
  }

  data = yield this.get(layout.c(hash, index));

  if (!data)
    return;

  credit = Credit.fromRaw(data);
  credit.coin.hash = hash;
  credit.coin.index = index;

  this.coinCache.set(key, data);

  return credit;
});

/**
 * Get spender coin.
 * @param {Outpoint} spent
 * @param {Outpoint} prevout
 * @returns {Promise} - Returns {@link Coin}.
 */

TXDB.prototype.getSpentCoin = co(function* getSpentCoin(spent, prevout) {
  var data = yield this.get(layout.d(spent.hash, spent.index));
  var coin;

  if (!data)
    return;

  coin = Coin.fromRaw(data);
  coin.hash = prevout.hash;
  coin.index = prevout.index;

  return coin;
});

/**
 * Test whether the database has a spent coin.
 * @param {Outpoint} spent
 * @returns {Promise} - Returns {@link Coin}.
 */

TXDB.prototype.hasSpentCoin = function hasSpentCoin(spent) {
  return this.has(layout.d(spent.hash, spent.index));
};

/**
 * Update spent coin height in storage.
 * @param {TX} tx - Sending transaction.
 * @param {Number} index
 * @returns {Promise}
 */

TXDB.prototype.updateSpentCoin = co(function* updateSpentCoin(tx, i) {
  var prevout = Outpoint.fromTX(tx, i);
  var spent = yield this.getSpent(prevout.hash, prevout.index);
  var coin;

  if (!spent)
    return;

  coin = yield this.getSpentCoin(spent, prevout);

  if (!coin)
    return;

  coin.height = tx.height;

  this.put(layout.d(spent.hash, spent.index), coin.toRaw());
});

/**
 * Test whether the database has a transaction.
 * @param {Hash} hash
 * @returns {Promise} - Returns Boolean.
 */

TXDB.prototype.hasCoin = function hasCoin(hash, index) {
  var key = hash + index;

  if (this.coinCache.has(key))
    return Promise.resolve(true);

  return this.has(layout.c(hash, index));
};

/**
 * Calculate balance.
 * @param {Number?} account
 * @returns {Promise} - Returns {@link Balance}.
 */

TXDB.prototype.getBalance = co(function* getBalance(account) {
  // Slow case
  if (account != null)
    return yield this.getAccountBalance(account);

  // Fast case
  return this.state.toBalance();
});

/**
 * Calculate balance.
 * @param {Number?} account
 * @returns {Promise} - Returns {@link Balance}.
 */

TXDB.prototype.getWalletBalance = co(function* getWalletBalance() {
  var credits = yield this.getCredits(null, true);
  var balance = new Balance(this.wallet.wid, this.wallet.id, -1);
  var i, credit;

  for (i = 0; i < credits.length; i++) {
    credit = credits[i];

    if (credit.coin.height !== -1)
      balance.confirmed += credit.coin.value;

    if (!credit.spent)
      balance.unconfirmed += credit.coin.value;
  }

  return balance;
});

/**
 * Calculate balance by account.
 * @param {Number} account
 * @returns {Promise} - Returns {@link Balance}.
 */

TXDB.prototype.getAccountBalance = co(function* getAccountBalance(account) {
  var credits = yield this.getAccountCredits(account, true);
  var balance = new Balance(this.wallet.wid, this.wallet.id, account);
  var i, credit;

  for (i = 0; i < credits.length; i++) {
    credit = credits[i];

    if (credit.coin.height !== -1)
      balance.confirmed += credit.coin.value;

    if (!credit.spent)
      balance.unconfirmed += credit.coin.value;
  }

  return balance;
});

/**
 * Zap pending transactions older than `age`.
 * @param {Number?} account
 * @param {Number} age - Age delta (delete transactions older than `now - age`).
 * @returns {Promise}
 */

TXDB.prototype.zap = co(function* zap(account, age) {
  var hashes = [];
  var now = utils.now();
  var i, txs, tx, hash;

  assert(utils.isUInt32(age));

  txs = yield this.getRange(account, {
    start: 0,
    end: now - age
  });

  for (i = 0; i < txs.length; i++) {
    tx = txs[i];
    hash = tx.hash('hex');

    if (tx.height !== -1)
      continue;

    assert(now - tx.ps >= age);

    this.logger.debug('Zapping TX: %s (%s)',
      hash, this.wallet.id);

    yield this.remove(hash);

    hashes.push(hash);
  }

  return hashes;
});

/**
 * Abandon transaction.
 * @param {Hash} hash
 * @returns {Promise}
 */

TXDB.prototype.abandon = co(function* abandon(hash) {
  var result = yield this.has(layout.p(hash));
  if (!result)
    throw new Error('TX not eligible.');
  return yield this.remove(hash);
});

/**
 * Balance
 * @constructor
 * @param {WalletID} wid
 * @param {String} id
 * @param {Number} account
 */

function Balance(wid, id, account) {
  if (!(this instanceof Balance))
    return new Balance(wid, id, account);

  this.wid = wid;
  this.id = id;
  this.account = account;
  this.unconfirmed = 0;
  this.confirmed = 0;
}

/**
 * Test whether a balance is equal.
 * @param {Balance} balance
 * @returns {Boolean}
 */

Balance.prototype.equal = function equal(balance) {
  return this.wid === balance.wid
    && this.confirmed === balance.confirmed
    && this.unconfirmed === balance.unconfirmed;
};

/**
 * Convert balance to a more json-friendly object.
 * @param {Boolean?} minimal
 * @returns {Object}
 */

Balance.prototype.toJSON = function toJSON(minimal) {
  return {
    wid: !minimal ? this.wid : undefined,
    id: !minimal ? this.id : undefined,
    account: !minimal ? this.account : undefined,
    unconfirmed: utils.btc(this.unconfirmed),
    confirmed: utils.btc(this.confirmed)
  };
};

/**
 * Convert balance to human-readable string.
 * @returns {String}
 */

Balance.prototype.toString = function toString() {
  return '<Balance'
    + ' unconfirmed=' + utils.btc(this.unconfirmed)
    + ' confirmed=' + utils.btc(this.confirmed)
    + '>';
};

/**
 * Inspect balance.
 * @param {String}
 */

Balance.prototype.inspect = function inspect() {
  return this.toString();
};

/**
 * Chain State
 * @constructor
 * @param {WalletID} wid
 * @param {String} id
 */

function TXDBState(wid, id) {
  this.wid = wid;
  this.id = id;
  this.tx = 0;
  this.coin = 0;
  this.unconfirmed = 0;
  this.confirmed = 0;
  this.committed = false;
}

/**
 * Clone the state.
 * @returns {TXDBState}
 */

TXDBState.prototype.clone = function clone() {
  var state = new TXDBState(this.wid, this.id);
  state.tx = this.tx;
  state.coin = this.coin;
  state.unconfirmed = this.unconfirmed;
  state.confirmed = this.confirmed;
  return state;
};

/**
 * Commit and serialize state.
 * @returns {Buffer}
 */

TXDBState.prototype.commit = function commit() {
  this.committed = true;
  return this.toRaw();
};

/**
 * Convert state to a balance object.
 * @returns {Balance}
 */

TXDBState.prototype.toBalance = function toBalance() {
  var balance = new Balance(this.wid, this.id, -1);
  balance.unconfirmed = this.unconfirmed;
  balance.confirmed = this.confirmed;
  return balance;
};

/**
 * Serialize state.
 * @returns {Buffer}
 */

TXDBState.prototype.toRaw = function toRaw(writer) {
  var p = new BufferWriter(writer);

  p.writeU64(this.tx);
  p.writeU64(this.coin);
  p.writeU64(this.unconfirmed);
  p.writeU64(this.confirmed);

  if (!writer)
    p = p.render();

  return p;
};

/**
 * Inject properties from serialized data.
 * @private
 * @param {Buffer} data
 * @returns {TXDBState}
 */

TXDBState.prototype.fromRaw = function fromRaw(data) {
  var p = new BufferReader(data);
  this.tx = p.readU53();
  this.coin = p.readU53();
  this.unconfirmed = p.readU53();
  this.confirmed = p.readU53();
  return this;
};

/**
 * Instantiate txdb state from serialized data.
 * @param {Buffer} data
 * @returns {TXDBState}
 */

TXDBState.fromRaw = function fromRaw(wid, id, data) {
  return new TXDBState(wid, id).fromRaw(data);
};

/**
 * Convert state to a more json-friendly object.
 * @param {Boolean?} minimal
 * @returns {Object}
 */

TXDBState.prototype.toJSON = function toJSON(minimal) {
  return {
    wid: !minimal ? this.wid : undefined,
    id: !minimal ? this.id : undefined,
    tx: this.tx,
    coin: this.coin,
    unconfirmed: utils.btc(this.unconfirmed),
    confirmed: utils.btc(this.confirmed)
  };
};

/**
 * Inspect the state.
 * @returns {Object}
 */

TXDBState.prototype.inspect = function inspect() {
  return this.toJSON();
};

/**
 * Transaction Details
 * @constructor
 * @param {TXDB} txdb
 * @param {TX} tx
 */

function Details(txdb, tx) {
  if (!(this instanceof Details))
    return new Details(txdb, tx);

  this.db = txdb.walletdb;
  this.network = this.db.network;
  this.wid = txdb.wallet.wid;
  this.id = txdb.wallet.id;
  this.hash = tx.hash('hex');
  this.height = tx.height;
  this.block = tx.block;
  this.index = tx.index;
  this.confirmations = tx.getConfirmations(this.db.height);
  this.fee = tx.getFee();
  this.ts = tx.ts;
  this.ps = tx.ps;
  this.tx = tx;

  this.inputs = [];
  this.outputs = [];
  this.accounts = [];

  this.init();
}

/**
 * Initialize transaction details.
 * @private
 */

Details.prototype.init = function init() {
  var i, input, output, member;

  for (i = 0; i < this.tx.inputs.length; i++) {
    input = this.tx.inputs[i];
    member = new DetailsMember();
    member.address = input.getAddress();
    this.inputs.push(member);
  }

  for (i = 0; i < this.tx.outputs.length; i++) {
    output = this.tx.outputs[i];
    member = new DetailsMember();
    member.value = output.value;
    member.address = output.getAddress();
    this.outputs.push(member);
  }
};

/**
 * Add necessary info to input member.
 * @param {Number} i
 * @param {Path} path
 * @param {Coin} coin
 */

Details.prototype.setInput = function setInput(i, path, coin) {
  var member = this.inputs[i];

  if (coin) {
    member.value = coin.value;
    member.address = coin.getAddress();
  }

  if (path) {
    member.path = path;
    utils.binaryInsert(this.accounts, path.account, cmp, true);
  }
};

/**
 * Add necessary info to output member.
 * @param {Number} i
 * @param {Path} path
 */

Details.prototype.setOutput = function setOutput(i, path) {
  var member = this.outputs[i];

  if (path) {
    member.path = path;
    utils.binaryInsert(this.accounts, path.account, cmp, true);
  }
};

/**
 * Convert details to a more json-friendly object.
 * @returns {Object}
 */

Details.prototype.toJSON = function toJSON() {
  var self = this;
  return {
    wid: this.wid,
    id: this.id,
    hash: utils.revHex(this.hash),
    height: this.height,
    block: this.block ? utils.revHex(this.block) : null,
    ts: this.ts,
    ps: this.ps,
    index: this.index,
    fee: utils.btc(this.fee),
    confirmations: this.confirmations,
    inputs: this.inputs.map(function(input) {
      return input.toJSON(self.network);
    }),
    outputs: this.outputs.map(function(output) {
      return output.toJSON(self.network);
    }),
    tx: this.tx.toRaw().toString('hex')
  };
};

/**
 * Transaction Details Member
 * @constructor
 * @property {Number} value
 * @property {Address} address
 * @property {Path} path
 */

function DetailsMember() {
  if (!(this instanceof DetailsMember))
    return new DetailsMember();

  this.value = 0;
  this.address = null;
  this.path = null;
}

/**
 * Convert the member to a more json-friendly object.
 * @param {Network} network
 * @returns {Object}
 */

DetailsMember.prototype.toJSON = function toJSON(network) {
  return {
    value: utils.btc(this.value),
    address: this.address
      ? this.address.toBase58(network)
      : null,
    path: this.path
      ? this.path.toJSON()
      : null
  };
};

/**
 * Credit (wrapped coin)
 * @constructor
 * @param {Coin} coin
 * @param {Boolean?} spent
 * @property {Coin} coin
 * @property {Boolean} spent
 */

function Credit(coin, spent) {
  if (!(this instanceof Credit))
    return new Credit(coin, spent);

  this.coin = coin || new Coin();
  this.spent = spent || false;
}

/**
 * Inject properties from serialized data.
 * @private
 * @param {Buffer} data
 */

Credit.prototype.fromRaw = function fromRaw(data) {
  var p = BufferReader(data);
  this.coin.fromRaw(p);
  this.spent = p.readU8() === 1;
  return this;
};

/**
 * Instantiate credit from serialized data.
 * @param {Buffer} data
 * @returns {Credit}
 */

Credit.fromRaw = function fromRaw(data) {
  return new Credit().fromRaw(data);
};

/**
 * Serialize credit.
 * @returns {Buffer}
 */

Credit.prototype.toRaw = function toRaw(writer) {
  var p = BufferWriter(writer);

  this.coin.toRaw(p);
  p.writeU8(this.spent ? 1 : 0);

  if (!writer)
    p = p.render();

  return p;
};

/**
 * Inject properties from tx object.
 * @private
 * @param {TX} tx
 * @param {Number} i
 * @returns {Credit}
 */

Credit.prototype.fromTX = function fromTX(tx, i) {
  this.coin.fromTX(tx, i);
  this.spent = false;
  return this;
};

/**
 * Instantiate credit from transaction.
 * @param {TX} tx
 * @param {Number} i
 * @returns {Credit}
 */

Credit.fromTX = function fromTX(tx, i) {
  return new Credit().fromTX(tx, i);
};

/*
 * Helpers
 */

function Orphan(tx, i) {
  this.tx = tx;
  this.hash = tx.hash('hex');
  this.index = i;
}

function cmp(a, b) {
  return a - b;
}

/*
 * Expose
 */

module.exports = TXDB;
