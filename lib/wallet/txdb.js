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
  S: function S(hash, index) {
    return layout.hi(0x53, hash, index);
  },
  Ss: function Ss(key) {
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
  this.spentCache = new LRU(10000);

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
 * @param {PathInfo} info
 */

TXDB.prototype.emit = function emit(event, data, info) {
  this.events.push([event, data, info]);
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
 * Map a transactions' addresses to wallet IDs.
 * @param {TX} tx
 * @returns {Promise} - Returns {@link PathInfo}.
 */

TXDB.prototype.getPathInfo = function getPathInfo(tx) {
  return this.wallet.getPathInfo(tx);
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
  var path, key, coin, spent;

  if (tx.isCoinbase())
    return true;

  if (this.count[hash])
    return false;

  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];
    prevout = input.prevout;

    spent = yield this.getSpent(prevout.hash, prevout.index);

    if (spent) {
      coin = yield this.getSpentCoin(spent, prevout);
      assert(coin);

      input.coin = coin;

      if (this.options.verify && tx.height === -1) {
        if (!(yield tx.verifyInputAsync(i)))
          return false;
      }

      continue;
    }

    coin = yield this.getCoin(prevout.hash, prevout.index);

    if (coin) {
      input.coin = coin;

      if (this.options.verify && tx.height === -1) {
        if (!(yield tx.verifyInputAsync(i)))
          return false;
      }

      continue;
    }

    path = yield this.wallet.hasPath(input.getAddress());

    if (!path)
      continue;

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
      input.coin = coin;

      assert(input.prevout.hash === hash);
      assert(input.prevout.index === i);

      if (this.options.verify && orphan.tx.height === -1)
        valid = yield orphan.tx.verifyInputAsync(orphan.index);

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
 * Retrieve coins for own inputs, remove
 * double spenders, and verify inputs.
 * @private
 * @param {TX} tx
 * @param {PathInfo} info
 * @returns {Promise}
 */

TXDB.prototype.removeConflicts = co(function* removeConflicts(tx, info) {
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
 * Add transaction, runs `confirm()` and `verify()`.
 * @param {TX} tx
 * @param {PathInfo} info
 * @returns {Promise}
 */

TXDB.prototype.add = co(function* add(tx) {
  var info = yield this.getPathInfo(tx);
  var result;

  this.start();

  try {
    result = yield this._add(tx, info);
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
 * @param {PathInfo} info
 * @returns {Promise}
 */

TXDB.prototype._add = co(function* add(tx, info) {
  var hash, path, account;
  var i, result, input, output, coin;
  var prevout, key, spender, raw;

  assert(!tx.mutable, 'Cannot add mutable TX to wallet.');

  if (tx.height === -1) {
    if (yield this.isDoubleSpend(tx))
      return false;
  } else {
    // This potentially removes double-spenders.
    yield this.removeConflicts(tx, info);
  }

  // Attempt to confirm tx before adding it.
  result = yield this.confirm(tx, info);

  // Ignore if we already have this tx.
  if (result)
    return true;

  hash = tx.hash('hex');

  this.put(layout.t(hash), tx.toExtended());

  if (tx.height === -1)
    this.put(layout.p(hash), DUMMY);
  else
    this.put(layout.h(tx.height, hash), DUMMY);

  this.put(layout.m(tx.ps, hash), DUMMY);

  for (i = 0; i < info.accounts.length; i++) {
    account = info.accounts[i];

    this.put(layout.T(account, hash), DUMMY);

    if (tx.height === -1)
      this.put(layout.P(account, hash), DUMMY);
    else
      this.put(layout.H(account, tx.height, hash), DUMMY);

    this.put(layout.M(account, tx.ps, hash), DUMMY);
  }

  // Consume unspent money or add orphans
  if (!tx.isCoinbase()) {
    for (i = 0; i < tx.inputs.length; i++) {
      input = tx.inputs[i];
      prevout = input.prevout;
      coin = yield this.getCoin(prevout.hash, prevout.index);

      // Only bother if this input is ours.
      if (!coin)
        continue;

      path = info.getPath(coin);
      assert(path);

      key = prevout.hash + prevout.index;

      spender = Outpoint.fromTX(tx, i).toRaw();

      this.put(layout.s(prevout.hash, prevout.index), spender);

      this.pending.unconfirmed -= coin.value;

      if (tx.height === -1) {
        this.put(layout.S(prevout.hash, prevout.index), spender);
        this.spentCache.set(key, spender);
      } else {
        this.pending.confirmed -= coin.value;
        this.del(layout.c(prevout.hash, prevout.index));
        this.del(layout.C(path.account, prevout.hash, prevout.index));
        this.coinCache.remove(key);
        this.pending.coin--;
      }

      this.put(layout.d(hash, i), coin.toRaw());
    }
  }

  // Add unspent outputs or resolve orphans.
  for (i = 0; i < tx.outputs.length; i++) {
    output = tx.outputs[i];
    path = info.getPath(output);
    key = hash + i;

    // Do not add unspents for
    // outputs that aren't ours.
    if (!path)
      continue;

    coin = Coin.fromTX(tx, i);
    raw = coin.toRaw();

    this.pending.unconfirmed += coin.value;

    if (tx.height !== -1)
      this.pending.confirmed += coin.value;

    this.put(layout.c(hash, i), raw);
    this.put(layout.C(path.account, hash, i), DUMMY);
    this.pending.coin++;

    this.coinCache.set(key, raw);
  }

  this.pending.tx++;
  this.put(layout.R, this.pending.commit());

  // Clear any locked coins to free up memory.
  this.unlockTX(tx);

  this.emit('tx', tx, info);

  if (tx.height !== -1)
    this.emit('confirmed', tx, info);

  this.emit('balance', this.pending.toBalance(), info);

  return true;
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
  var info;

  assert(tx);

  this.logger.warning('Handling conflicting tx: %s.', utils.revHex(hash));

  this.drop();

  info = yield this.removeRecursive(tx);

  this.start();

  this.logger.warning('Removed conflict: %s.', tx.rhash);

  // Emit the _removed_ transaction.
  this.emit('conflict', tx, info);
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
  var i, spent, stx, info;

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
  info = yield this.lazyRemove(tx);

  assert(info);

  yield this.commit();

  return info;
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

TXDB.prototype.getSpending = co(function* getSpending(hash, index) {
  var key = hash + index;
  var data = this.spentCache.get(key);

  if (data)
    return Outpoint.fromRaw(data);

  data = yield this.get(layout.S(hash, index));

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
 * Test a whether a coin has been spent.
 * @param {Hash} hash
 * @param {Number} index
 * @returns {Promise} - Returns Boolean.
 */

TXDB.prototype.isSpending = co(function* isSpending(hash, index) {
  var key = hash + index;
  var data = this.spentCache.get(key);

  if (data)
    return true;

  data = yield this.get(layout.S(hash, index));

  return data != null;
});

/**
 * Attempt to confirm a transaction.
 * @private
 * @param {TX} tx
 * @param {AddressMap} info
 * @returns {Promise} - Returns Boolean. `false` if
 * the transaction should be added to the database, `true` if the
 * transaction was confirmed, or should be ignored.
 */

TXDB.prototype.confirm = co(function* confirm(tx, info) {
  var hash = tx.hash('hex');
  var i, account, existing, output, coin;
  var input, prevout, path, spender, coins;
  var key, raw;

  existing = yield this.getTX(hash);

  // Haven't seen this tx before, add it.
  if (!existing)
    return false;

  // Existing tx is already confirmed. Ignore.
  if (existing.height !== -1)
    return true;

  // The incoming tx won't confirm the
  // existing one anyway. Ignore.
  if (tx.height === -1)
    return true;

  // Inject block properties.
  existing.ts = tx.ts;
  existing.height = tx.height;
  existing.index = tx.index;
  existing.block = tx.block;
  tx = existing;

  this.put(layout.t(hash), tx.toExtended());

  this.del(layout.p(hash));
  this.put(layout.h(tx.height, hash), DUMMY);

  for (i = 0; i < info.accounts.length; i++) {
    account = info.accounts[i];
    this.del(layout.P(account, hash));
    this.put(layout.H(account, tx.height, hash), DUMMY);
  }

  // Consume unspent money or add orphans
  if (!tx.isCoinbase()) {
    coins = yield this.fillHistory(tx);

    for (i = 0; i < tx.inputs.length; i++) {
      input = tx.inputs[i];
      prevout = input.prevout;
      coin = coins[i];

      if (!coin) {
        coin = yield this.getCoin(prevout.hash, prevout.index);

        if (!coin)
          continue;

        spender = Outpoint.fromTX(tx, i).toRaw();

        this.put(layout.d(hash, i), coin.toRaw());
        this.put(layout.s(prevout.hash, prevout.index), spender);

        this.pending.unconfirmed -= coin.value;
      }

      assert(coin.height !== -1);

      // Only bother if this input is ours.
      path = info.getPath(coin);
      assert(path);

      key = prevout.hash + prevout.index;

      this.del(layout.S(prevout.hash, prevout.index));
      this.del(layout.c(prevout.hash, prevout.index));
      this.del(layout.C(path.account, prevout.hash, prevout.index));

      this.pending.coin--;
      this.pending.confirmed -= coin.value;

      this.spentCache.remove(key);
      this.coinCache.remove(key);
    }
  }

  for (i = 0; i < tx.outputs.length; i++) {
    output = tx.outputs[i];
    key = hash + i;

    // Only update coins if this output is ours.
    if (!info.hasPath(output))
      continue;

    // Update spent coin.
    yield this.updateSpentCoin(tx, i);

    coin = yield this.getCoin(hash, i);

    if (!coin)
      continue;

    coin.height = tx.height;
    raw = coin.toRaw();

    this.pending.confirmed += coin.value;
    this.pending.coin++;

    this.put(layout.c(hash, i), raw);

    this.coinCache.set(key, raw);
  }

  this.put(layout.R, this.pending.commit());

  // Clear any locked coins to free up memory.
  this.unlockTX(tx);

  this.emit('tx', tx, info);
  this.emit('confirmed', tx, info);
  this.emit('balance', this.pending.toBalance(), info);

  return true;
});

/**
 * Remove a transaction from the database. Disconnect inputs.
 * @param {Hash} hash
 * @returns {Promise}
 */

TXDB.prototype.remove = co(function* remove(hash) {
  var result;

  this.start();

  try {
    result = yield this._remove(hash);
  } catch (e) {
    this.drop();
    throw e;
  }

  yield this.commit();

  return result;
});

/**
 * Remove a transaction without a lock.
 * @private
 * @param {Hash} hash
 * @returns {Promise}
 */

TXDB.prototype._remove = co(function* remove(hash) {
  var tx = yield this.getTX(hash);
  var info;

  if (!tx)
    return;

  this.drop();

  info = yield this.removeRecursive(tx);

  this.start();

  if (!info)
    return;

  return info;
});

/**
 * Remove a transaction from the database, but do not
 * look up the transaction. Use the passed-in transaction
 * to disconnect.
 * @param {TX} tx
 * @returns {Promise}
 */

TXDB.prototype.lazyRemove = co(function* lazyRemove(tx) {
  var info = yield this.getPathInfo(tx);
  if (!info)
    return;

  return yield this.__remove(tx, info);
});

/**
 * Remove a transaction from the database. Disconnect inputs.
 * @private
 * @param {TX} tx
 * @param {AddressMap} info
 * @returns {Promise}
 */

TXDB.prototype.__remove = co(function* remove(tx, info) {
  var hash = tx.hash('hex');
  var i, path, account, key, prevout;
  var input, output, coin, coins, raw;

  this.del(layout.t(hash));

  if (tx.height === -1)
    this.del(layout.p(hash));
  else
    this.del(layout.h(tx.height, hash));

  this.del(layout.m(tx.ps, hash));

  for (i = 0; i < info.accounts.length; i++) {
    account = info.accounts[i];

    this.del(layout.T(account, hash));

    if (tx.height === -1)
      this.del(layout.P(account, hash));
    else
      this.del(layout.H(account, tx.height, hash));

    this.del(layout.M(account, tx.ps, hash));
  }

  if (!tx.isCoinbase()) {
    coins = yield this.fillHistory(tx);

    for (i = 0; i < tx.inputs.length; i++) {
      input = tx.inputs[i];
      key = input.prevout.hash + input.prevout.index;
      prevout = input.prevout;
      coin = coins[i];

      if (!coin)
        continue;

      path = info.getPath(coin);
      assert(path);

      this.pending.unconfirmed += coin.value;

      this.del(layout.s(prevout.hash, prevout.index));

      if (tx.height !== -1) {
        raw = coin.toRaw();
        this.pending.confirmed += coin.value;
        this.pending.coin++;
        this.put(layout.c(prevout.hash, prevout.index), raw);
        this.put(layout.C(path.account, prevout.hash, prevout.index), DUMMY);
        this.coinCache.set(key, raw);
      } else {
        this.del(layout.S(prevout.hash, prevout.index));
        this.spentCache.remove(key);
      }

      this.del(layout.d(hash, i));
    }
  }

  for (i = 0; i < tx.outputs.length; i++) {
    output = tx.outputs[i];
    key = hash + i;
    path = info.getPath(output);

    if (!path)
      continue;

    coin = Coin.fromTX(tx, i);

    this.pending.coin--;
    this.pending.unconfirmed -= coin.value;

    if (tx.height !== -1)
      this.pending.confirmed -= coin.value;

    this.del(layout.c(hash, i));
    this.del(layout.C(path.account, hash, i));

    this.coinCache.remove(key);
  }

  this.pending.tx--;
  this.put(layout.R, this.pending.commit());

  this.emit('remove tx', tx, info);
  this.emit('balance', this.pending.toBalance(), info);

  return info;
});

/**
 * Unconfirm a transaction. This is usually necessary after a reorg.
 * @param {Hash} hash
 * @returns {Promise}
 */

TXDB.prototype.unconfirm = co(function* unconfirm(hash) {
  var result;

  this.start();

  try {
    result = yield this._unconfirm(hash);
  } catch (e) {
    this.drop();
    throw e;
  }

  yield this.commit();

  return result;
});

/**
 * Unconfirm a transaction without a lock.
 * @private
 * @param {Hash} hash
 * @returns {Promise}
 */

TXDB.prototype._unconfirm = co(function* unconfirm(hash) {
  var tx = yield this.getTX(hash);
  var info, result;

  if (!tx)
    return false;

  info = yield this.getPathInfo(tx);

  if (!info)
    return false;

  result = yield this.__unconfirm(tx, info);

  return result;
});

/**
 * Unconfirm a transaction. This is usually necessary after a reorg.
 * @param {Hash} hash
 * @param {AddressMap} info
 * @returns {Promise}
 */

TXDB.prototype.__unconfirm = co(function* unconfirm(tx, info) {
  var hash = tx.hash('hex');
  var height = tx.height;
  var i, account, output, key, coin, coins;
  var input, prevout, path, spender, raw;

  if (height === -1)
    return;

  tx.unsetBlock();

  this.put(layout.t(hash), tx.toExtended());

  this.put(layout.p(hash), DUMMY);
  this.del(layout.h(height, hash));

  for (i = 0; i < info.accounts.length; i++) {
    account = info.accounts[i];
    this.put(layout.P(account, hash), DUMMY);
    this.del(layout.H(account, height, hash));
  }

  // Consume unspent money or add orphans
  if (!tx.isCoinbase()) {
    coins = yield this.fillHistory(tx);

    for (i = 0; i < tx.inputs.length; i++) {
      input = tx.inputs[i];
      prevout = input.prevout;
      coin = coins[i];

      // Only bother if this input is ours.
      if (!coin)
        continue;

      assert(coin.height !== -1);

      raw = coin.toRaw();

      path = info.getPath(coin);
      assert(path);

      key = prevout.hash + prevout.index;

      spender = Outpoint.fromTX(tx, i).toRaw();

      this.put(layout.S(prevout.hash, prevout.index), spender);
      this.put(layout.c(prevout.hash, prevout.index), raw);
      this.put(layout.C(path.account, prevout.hash, prevout.index), DUMMY);

      this.pending.coin++;
      this.pending.confirmed += coin.value;

      this.spentCache.set(key, spender);
      this.coinCache.set(key, raw);
    }
  }

  for (i = 0; i < tx.outputs.length; i++) {
    output = tx.outputs[i];
    key = hash + i;

    // Update spent coin.
    yield this.updateSpentCoin(tx, i);

    coin = yield this.getCoin(hash, i);

    if (!coin)
      continue;

    coin.height = -1;
    raw = coin.toRaw();

    this.pending.confirmed -= coin.value;
    this.pending.coin++;

    this.put(layout.c(hash, i), raw);

    this.coinCache.set(key, raw);
  }

  this.put(layout.R, this.pending.commit());

  this.emit('unconfirmed', tx, info);
  this.emit('balance', this.pending.toBalance(), info);

  return info;
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
  var txs = [];
  var i, hashes, hash, tx;

  hashes = yield this.getHistoryHashes(account);

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
  var txs = [];
  var i, hashes, hash, tx;

  hashes = yield this.getPendingHashes(account);

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
  var self = this;
  var out = [];
  var i, coins, coin;

  // Slow case
  if (account != null)
    return this.getAccountCoins(account);

  // Fast case
  coins = yield this.range({
    gte: layout.c(constants.NULL_HASH, 0x00000000),
    lte: layout.c(constants.HIGH_HASH, 0xffffffff),
    parse: function(key, value) {
      var parts = layout.cc(key);
      var hash = parts[0];
      var index = parts[1];
      var coin = Coin.fromRaw(value);
      var ckey = hash + index;
      coin.hash = hash;
      coin.index = index;
      self.coinCache.set(ckey, value);
      return coin;
    }
  });

  if (all)
    return coins;

  for (i = 0; i < coins.length; i++) {
    coin = coins[i];
    if (yield this.isSpending(coin.hash, coin.index))
      continue;
    out.push(coin);
  }

  return out;
});

/**
 * Get coins by account.
 * @param {Number} account
 * @returns {Promise} - Returns {@link Coin}[].
 */

TXDB.prototype.getAccountCoins = co(function* getCoins(account, all) {
  var prevout = yield this.getOutpoints(account);
  var coins = [];
  var i, op, coin;

  for (i = 0; i < prevout.length; i++) {
    op = prevout[i];
    coin = yield this.getCoin(op.hash, op.index);

    if (!coin)
      continue;

    if (!all) {
      if (yield this.isSpending(coin.hash, coin.index))
        continue;
    }

    coins.push(coin);
  }

  return coins;
});

/**
 * Fill a transaction with coins (all historical coins).
 * @param {TX} tx
 * @returns {Promise} - Returns {@link TX}.
 */

TXDB.prototype.fillHistory = co(function* fillHistory(tx) {
  var coins = [];
  var hash;

  if (tx.isCoinbase())
    return coins;

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
      input.coin = coin;
      coins[index] = coin;
    }
  });

  return coins;
});

/**
 * Fill a transaction with coins.
 * @param {TX} tx
 * @returns {Promise} - Returns {@link TX}.
 */

TXDB.prototype.fillCoins = co(function* fillCoins(tx) {
  var i, input, prevout, coin;

  if (tx.isCoinbase())
    return tx;

  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];
    prevout = input.prevout;

    if (input.coin)
      continue;

    coin = yield this.getCoin(prevout.hash, prevout.index);

    if (!coin)
      continue;

    if (yield this.isSpending(coin.hash, coin.index))
      continue;

    input.coin = coin;
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
  var i, out, txs, details, info;

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

  yield this.fillHistory(tx);

  info = yield this.getPathInfo(tx);

  if (!info)
    throw new Error('Info not found.');

  return info.toDetails();
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
  var key = hash + index;
  var data = this.coinCache.get(key);
  var coin;

  if (data) {
    coin = Coin.fromRaw(data);
    coin.hash = hash;
    coin.index = index;
    return coin;
  }

  data = yield this.get(layout.c(hash, index));

  if (!data)
    return;

  coin = Coin.fromRaw(data);
  coin.hash = hash;
  coin.index = index;

  this.coinCache.set(key, data);

  return coin;
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
  var coins = yield this.getCoins(true);
  var balance = new Balance(this.wallet.wid, this.wallet.id, -1);
  var i, coin;

  for (i = 0; i < coins.length; i++) {
    coin = coins[i];

    if (coin.height !== -1)
      balance.confirmed += coin.value;

    if (!(yield this.isSpending(coin.hash, coin.index)))
      balance.unconfirmed += coin.value;
  }

  return balance;
});

/**
 * Calculate balance by account.
 * @param {Number} account
 * @returns {Promise} - Returns {@link Balance}.
 */

TXDB.prototype.getAccountBalance = co(function* getAccountBalance(account) {
  var coins = yield this.getAccountCoins(account, true);
  var balance = new Balance(this.wallet.wid, this.wallet.id, account);
  var i, coin;

  for (i = 0; i < coins.length; i++) {
    coin = coins[i];

    if (coin.height !== -1)
      balance.confirmed += coin.value;

    if (!(yield this.isSpending(coin.hash, coin.index)))
      balance.unconfirmed += coin.value;
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

/*
 * Balance
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

Balance.prototype.equal = function equal(balance) {
  return this.wid === balance.wid
    && this.confirmed === balance.confirmed
    && this.unconfirmed === balance.unconfirmed;
};

Balance.prototype.toJSON = function toJSON(minimal) {
  return {
    wid: !minimal ? this.wid : undefined,
    id: !minimal ? this.id : undefined,
    account: !minimal ? this.account : undefined,
    unconfirmed: utils.btc(this.unconfirmed),
    confirmed: utils.btc(this.confirmed)
  };
};

Balance.prototype.toString = function toString() {
  return '<Balance'
    + ' unconfirmed=' + utils.btc(this.unconfirmed)
    + ' confirmed=' + utils.btc(this.confirmed)
    + '>';
};

Balance.prototype.inspect = function inspect() {
  return this.toString();
};

/**
 * Chain State
 * @constructor
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

TXDBState.prototype.clone = function clone() {
  var state = new TXDBState(this.wid, this.id);
  state.tx = this.tx;
  state.coin = this.coin;
  state.unconfirmed = this.unconfirmed;
  state.confirmed = this.confirmed;
  return state;
};

TXDBState.prototype.commit = function commit() {
  this.committed = true;
  return this.toRaw();
};

TXDBState.prototype.toBalance = function toBalance() {
  var balance = new Balance(this.wid, this.id, -1);
  balance.unconfirmed = this.unconfirmed;
  balance.confirmed = this.confirmed;
  return balance;
};

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

TXDBState.prototype.fromRaw = function fromRaw(data) {
  var p = new BufferReader(data);
  this.tx = p.readU53();
  this.coin = p.readU53();
  this.unconfirmed = p.readU53();
  this.confirmed = p.readU53();
  return this;
};

TXDBState.fromRaw = function fromRaw(wid, id, data) {
  return new TXDBState(wid, id).fromRaw(data);
};

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

TXDBState.prototype.inspect = function inspect() {
  return this.toJSON();
};

/*
 * Helpers
 */

function Orphan(tx, i) {
  this.tx = tx;
  this.hash = tx.hash('hex');
  this.index = i;
}

/*
 * Expose
 */

module.exports = TXDB;
