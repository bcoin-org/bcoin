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
  o: function o(hash, index) {
    return layout.hi(0x6f, hash, index);
  },
  oo: function oo(key) {
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
  this.locked = {};

  this.coinCache = new LRU(10000);
  this.balance = null;
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
  this.balance = yield this.getBalance();
  this.logger.info('TXDB loaded for %s.', this.wallet.id);
  this.logger.info(
    'Balance: unconfirmed=%s confirmed=%s total=%s.',
    utils.btc(this.balance.unconfirmed),
    utils.btc(this.balance.confirmed),
    utils.btc(this.balance.total));
});

/**
 * Emit transaction event.
 * @private
 * @param {String} event
 * @param {TX} tx
 * @param {PathInfo} info
 */

TXDB.prototype.emit = function emit(event, tx, info) {
  this.walletdb.emit(event, info.id, tx, info);
  this.wallet.emit(event, tx, info);
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
 * Add an orphan (tx hash + input index)
 * to orphan list. Stored by its required coin ID.
 * @private
 * @param {Outpoint} prevout - Required coin hash & index.
 * @param {Buffer} input - Spender input hash and index.
 * @returns {Promise} - Returns Buffer.
 */

TXDB.prototype.addOrphan = co(function* addOrphan(prevout, input) {
  var key = layout.o(prevout.hash, prevout.index);
  var data = yield this.get(key);
  var p = new BufferWriter();

  if (data)
    p.writeBytes(data);

  p.writeBytes(input);

  this.put(key, p.render());
});

/**
 * Retrieve orphan list by coin ID.
 * @private
 * @param {Hash} hash
 * @param {Number} index
 * @returns {Promise} - Returns {@link Orphan}.
 */

TXDB.prototype.getOrphans = co(function* getOrphans(hash, index) {
  var key = layout.o(hash, index);
  var data = yield this.get(key);
  var items = [];
  var i, inputs, input, tx, p;

  if (!data)
    return;

  p = new BufferReader(data);
  inputs = [];

  while (p.left())
    inputs.push(Outpoint.fromRaw(p));

  for (i = 0; i < inputs.length; i++) {
    input = inputs[i];
    tx = yield this.getTX(input.hash);
    items.push(new Orphan(input, tx));
  }

  return items;
});

/**
 * Retrieve coins for own inputs, remove
 * double spenders, and verify inputs.
 * @private
 * @param {TX} tx
 * @param {PathInfo} info
 * @returns {Promise}
 */

TXDB.prototype.verify = co(function* verify(tx, info) {
  var spends = [];
  var orphans = [];
  var removed = {};
  var i, input, prevout, address, coin, spent, conflict;

  if (tx.isCoinbase())
    return orphans;

  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];
    prevout = input.prevout;
    address = input.getHash('hex');

    // Only bother if this input is ours.
    if (!info.hasPath(address))
      continue;

    coin = yield this.getCoin(prevout.hash, prevout.index);

    if (coin) {
      // Add TX to inputs and spend money
      input.coin = coin;

      // Skip invalid transactions
      if (this.options.verify) {
        if (!(yield tx.verifyInputAsync(i)))
          return;
      }

      continue;
    }

    spent = yield this.isSpent(prevout.hash, prevout.index);

    // Orphan until we see a parent transaction.
    if (!spent) {
      orphans[i] = true;
      continue;
    }

    // We must be double-spending.
    coin = yield this.getSpentCoin(spent, prevout);

    if (!coin)
      throw new Error('Could not find double-spent coin.');

    input.coin = coin;

    // Skip invalid transactions
    if (this.options.verify) {
      if (!(yield tx.verifyInputAsync(i)))
        return;
    }

    spends[i] = spent;
  }

  // Once we've verified everything to the
  // best of our ability, go through and
  // attempt to remove double-spenders.
  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];
    prevout = input.prevout;
    spent = spends[i];

    if (!spent)
      continue;

    this.logger.warning('Handling conflicting tx: %s.',
      utils.revHex(spent.hash));

    // Remove the older double spender.
    // We have to maintain a spent list
    // and pass it in. It needs to know
    // which txs are considered "deleted"
    // within this context.
    conflict = yield this.removeConflict(spent.hash, tx, removed);

    // Spender was not removed, the current
    // transaction is not elligible to be added.
    // Be sure to clear the batch, lest we
    // remove other transactions on behalf of
    // a non-eligible tx.
    if (!conflict) {
      this.wallet.clear();
      return;
    }

    this.logger.warning('Removed conflict: %s.', conflict.tx.rhash);

    // Emit the _removed_ transaction.
    this.emit('conflict', conflict.tx, conflict.info);
  }

  return orphans;
});

/**
 * Attempt to resolve orphans for an output.
 * @private
 * @param {TX} tx
 * @param {Number} index
 * @returns {Promise}
 */

TXDB.prototype.resolveOrphans = co(function* resolveOrphans(tx, index) {
  var hash = tx.hash('hex');
  var i, orphans, coin, input, spender, orphan;

  orphans = yield this.getOrphans(hash, index);

  if (!orphans)
    return false;

  this.del(layout.o(hash, index));

  coin = Coin.fromTX(tx, index);

  // Add input to resolved orphan.
  for (i = 0; i < orphans.length; i++) {
    orphan = orphans[i];
    spender = orphan.input;
    tx = orphan.tx;

    // Probably removed by some other means.
    if (!tx)
      continue;

    input = tx.inputs[spender.index];
    input.coin = coin;

    assert(input.prevout.hash === hash);
    assert(input.prevout.index === index);

    // Verify that input script is correct, if not - add
    // output to unspent and remove orphan from storage
    if (!this.options.verify || (yield tx.verifyInputAsync(spender.index))) {
      // Add the undo coin record which we never had.
      this.put(layout.d(spender.hash, spender.index), coin.toRaw());
      // Add the spender record back in case any evil
      // transactions were removed with lazyRemove.
      this.put(layout.s(hash, index), spender.toRaw());
      return true;
    }

    yield this.lazyRemove(tx);
  }

  // We had orphans, but they were invalid. The
  // balance will be (incorrectly) added outside.
  // Subtract to compensate.
  this.balance.sub(coin);

  return false;
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

  this.wallet.start();

  try {
    result = yield this._add(tx, info);
  } catch (e) {
    this.wallet.drop();
    throw e;
  }

  yield this.wallet.commit();

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
  var prevout, key, address, spender, orphans;

  assert(!tx.mutable, 'Cannot add mutable TX to wallet.');

  // Attempt to confirm tx before adding it.
  result = yield this.confirm(tx, info);

  // Ignore if we already have this tx.
  if (result)
    return true;

  // Verify and get coins.
  // This potentially removes double-spenders.
  orphans = yield this.verify(tx, info);

  if (!orphans)
    return false;

  hash = tx.hash('hex');

  this.put(layout.t(hash), tx.toExtended());

  if (tx.ts === 0)
    this.put(layout.p(hash), DUMMY);
  else
    this.put(layout.h(tx.height, hash), DUMMY);

  this.put(layout.m(tx.ps, hash), DUMMY);

  for (i = 0; i < info.accounts.length; i++) {
    account = info.accounts[i];

    this.put(layout.T(account, hash), DUMMY);

    if (tx.ts === 0)
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

      address = input.getHash('hex');
      path = info.getPath(address);

      // Only bother if this input is ours.
      if (!path)
        continue;

      key = prevout.hash + prevout.index;

      // s[outpoint-key] -> [spender-hash]|[spender-input-index]
      spender = Outpoint.fromTX(tx, i).toRaw();
      this.put(layout.s(prevout.hash, prevout.index), spender);

      // Add orphan if no parent transaction known.
      // Do not disconnect any coins.
      if (orphans[i]) {
        yield this.addOrphan(prevout, spender);
        continue;
      }

      this.del(layout.c(prevout.hash, prevout.index));
      this.del(layout.C(path.account, prevout.hash, prevout.index));
      this.put(layout.d(hash, i), input.coin.toRaw());
      this.balance.sub(input.coin);

      this.coinCache.remove(key);
    }
  }

  // Add unspent outputs or resolve orphans
  for (i = 0; i < tx.outputs.length; i++) {
    output = tx.outputs[i];
    address = output.getHash('hex');
    key = hash + i;

    path = info.getPath(address);

    // Do not add unspents for outputs that aren't ours.
    if (!path)
      continue;

    orphans = yield this.resolveOrphans(tx, i);

    // If this transaction resolves an orphan,
    // it should not connect coins as they are
    // already spent by the orphan it resolved.
    if (orphans)
      continue;

    coin = Coin.fromTX(tx, i);

    this.balance.add(coin);

    coin = coin.toRaw();

    this.put(layout.c(hash, i), coin);
    this.put(layout.C(path.account, hash, i), DUMMY);

    this.coinCache.set(key, coin);
  }

  // Clear any locked coins to free up memory.
  this.unlockTX(tx);

  this.emit('tx', tx, info);

  if (tx.ts !== 0)
    this.emit('confirmed', tx, info);

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

TXDB.prototype.removeConflict = co(function* removeConflict(hash, ref, removed) {
  var tx = yield this.getTX(hash);
  var info;

  if (!tx)
    throw new Error('Could not find spender.');

  if (tx.ts !== 0) {
    // If spender is confirmed and replacement
    // is not confirmed, do nothing.
    if (ref.ts === 0)
      return;

    // If both are confirmed but replacement
    // is older than spender, do nothing.
    if (ref.height < tx.height)
      return;
  } else {
    // If spender is unconfirmed and replacement
    // is confirmed, do nothing.
    if (ref.ts !== 0)
      return;

    // If both are unconfirmed but replacement
    // is older than spender, do nothing.
    if (ref.ps < tx.ps)
      return;
  }

  info = yield this.removeRecursive(tx, removed);

  return new Conflict(tx, info);
});

/**
 * Remove a transaction and recursively
 * remove all of its spenders.
 * @private
 * @param {TX} tx - Transaction to be removed.
 * @returns {Promise} - Returns Boolean.
 */

TXDB.prototype.removeRecursive = co(function* removeRecursive(tx, removed) {
  var hash = tx.hash('hex');
  var i, spent, stx, info;

  if (!removed)
    removed = {};

  for (i = 0; i < tx.outputs.length; i++) {
    spent = yield this.isSpent(hash, i);

    if (!spent)
      continue;

    if (removed[spent.hash])
      continue;

    removed[spent.hash] = true;

    // Remove all of the spender's spenders first.
    stx = yield this.getTX(spent.hash);

    if (!stx)
      throw new Error('Could not find spender.');

    yield this.removeRecursive(stx, removed);
  }

  // Remove the spender.
  info = yield this.lazyRemove(tx);

  if (!info)
    throw new Error('Cannot remove spender.');

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

TXDB.prototype.isSpent = co(function* isSpent(hash, index) {
  var key = layout.s(hash, index);
  var data = yield this.get(key);

  if (!data)
    return;

  return Outpoint.fromRaw(data);
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
  var address, key;

  existing = yield this.getTX(hash);

  // Haven't seen this tx before, add it.
  if (!existing)
    return false;

  // Existing tx is already confirmed. Ignore.
  if (existing.ts !== 0)
    return true;

  // The incoming tx won't confirm the
  // existing one anyway. Ignore.
  if (tx.ts === 0)
    return true;

  // Tricky - update the tx and coin in storage,
  // and remove pending flag to mark as confirmed.
  assert(tx.height >= 0);

  // Clear any locked coins to free up memory.
  this.unlockTX(tx);

  // Save the original received time.
  tx.ps = existing.ps;

  this.put(layout.t(hash), tx.toExtended());

  this.del(layout.p(hash));
  this.put(layout.h(tx.height, hash), DUMMY);

  for (i = 0; i < info.accounts.length; i++) {
    account = info.accounts[i];
    this.del(layout.P(account, hash));
    this.put(layout.H(account, tx.height, hash), DUMMY);
  }

  for (i = 0; i < tx.outputs.length; i++) {
    output = tx.outputs[i];
    address = output.getHash('hex');
    key = hash + i;

    // Only update coins if this output is ours.
    if (!info.hasPath(address))
      continue;

    coin = yield this.getCoin(hash, i);

    // Update spent coin.
    if (!coin) {
      yield this.updateSpentCoin(tx, i);
      continue;
    }

    this.balance.confirm(coin.value);

    coin.height = tx.height;
    coin = coin.toRaw();

    this.put(layout.c(hash, i), coin);

    this.coinCache.set(key, coin);
  }

  this.emit('tx', tx, info);
  this.emit('confirmed', tx, info);

  return true;
});

/**
 * Remove a transaction from the database. Disconnect inputs.
 * @param {Hash} hash
 * @returns {Promise}
 */

TXDB.prototype.remove = co(function* remove(hash) {
  var result;

  this.wallet.start();

  try {
    result = yield this._remove(hash);
  } catch (e) {
    this.wallet.drop();
    throw e;
  }

  yield this.wallet.commit();

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

  info = yield this.removeRecursive(tx);

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
  var address, input, output, coin;

  this.del(layout.t(hash));

  if (tx.ts === 0)
    this.del(layout.p(hash));
  else
    this.del(layout.h(tx.height, hash));

  this.del(layout.m(tx.ps, hash));

  for (i = 0; i < info.accounts.length; i++) {
    account = info.accounts[i];

    this.del(layout.T(account, hash));

    if (tx.ts === 0)
      this.del(layout.P(account, hash));
    else
      this.del(layout.H(account, tx.height, hash));

    this.del(layout.M(account, tx.ps, hash));
  }

  if (!tx.isCoinbase()) {
    yield this.fillHistory(tx);

    for (i = 0; i < tx.inputs.length; i++) {
      input = tx.inputs[i];
      key = input.prevout.hash + input.prevout.index;
      prevout = input.prevout;
      address = input.getHash('hex');

      if (!input.coin)
        continue;

      path = info.getPath(address);

      if (!path)
        continue;

      this.balance.add(input.coin);

      coin = input.coin.toRaw();

      this.put(layout.c(prevout.hash, prevout.index), coin);
      this.put(layout.C(path.account, prevout.hash, prevout.index), DUMMY);
      this.del(layout.d(hash, i));
      this.del(layout.s(prevout.hash, prevout.index));
      this.del(layout.o(prevout.hash, prevout.index));

      this.coinCache.set(key, coin);
    }
  }

  for (i = 0; i < tx.outputs.length; i++) {
    output = tx.outputs[i];
    key = hash + i;
    address = output.getHash('hex');

    path = info.getPath(address);

    if (!path)
      continue;

    coin = Coin.fromTX(tx, i);

    this.balance.sub(coin);

    this.del(layout.c(hash, i));
    this.del(layout.C(path.account, hash, i));

    this.coinCache.remove(key);
  }

  this.emit('remove tx', tx, info);

  return info;
});

/**
 * Unconfirm a transaction. This is usually necessary after a reorg.
 * @param {Hash} hash
 * @returns {Promise}
 */

TXDB.prototype.unconfirm = co(function* unconfirm(hash) {
  var result;

  this.wallet.start();

  try {
    result = yield this._unconfirm(hash);
  } catch (e) {
    this.wallet.drop();
    throw e;
  }

  yield this.wallet.commit();

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
  var i, account, output, key, coin;

  if (height === -1)
    return;

  tx.height = -1;
  tx.ts = 0;
  tx.index = -1;
  tx.block = null;

  this.put(layout.t(hash), tx.toExtended());

  this.put(layout.p(hash), DUMMY);
  this.del(layout.h(height, hash));

  for (i = 0; i < info.accounts.length; i++) {
    account = info.accounts[i];
    this.put(layout.P(account, hash), DUMMY);
    this.del(layout.H(account, height, hash));
  }

  for (i = 0; i < tx.outputs.length; i++) {
    output = tx.outputs[i];
    key = hash + i;
    coin = yield this.getCoin(hash, i);

    // Update spent coin.
    if (!coin) {
      yield this.updateSpentCoin(tx, i);
      continue;
    }

    this.balance.unconfirm(coin.value);

    coin.height = tx.height;
    coin = coin.toRaw();

    this.put(layout.c(hash, i), coin);

    this.coinCache.set(key, coin);
  }

  this.emit('unconfirmed', tx, info);

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

TXDB.prototype.getHistoryHashes = function getHistoryHashes(account) {
  if (acount != null) {
    return this.keys({
      gte: layout.T(account, constants.NULL_HASH),
      lte: layout.T(account, constants.HIGH_HASH),
      parse: function(key) {
        key = layout.Tt(key);
        return key[1];
      }
    });
  }

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

TXDB.prototype.getUnconfirmedHashes = function getUnconfirmedHashes(account) {
  if (acount != null) {
    return this.keys({
      gte: layout.P(account, constants.NULL_HASH),
      lte: layout.P(account, constants.HIGH_HASH),
      parse: function(key) {
        key = layout.Pp(key);
        return key[1];
      }
    });
  }

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

TXDB.prototype.getOutpoints = function getOutpoints(account) {
  if (account != null) {
    return this.keys({
      gte: layout.C(account, constants.NULL_HASH, 0),
      lte: layout.C(account, constants.HIGH_HASH, 0xffffffff),
      parse: function(key) {
        key = layout.Cc(key);
        return new Outpoint(key[1], key[2]);
      }
    });
  }

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

TXDB.prototype.getHeightRangeHashes = function getHeightRangeHashes(account, options) {
  var start, end;

  if (account && typeof account === 'object') {
    options = account;
    account = null;
  }

  start = options.start || 0;
  end = options.end || 0xffffffff;

  if (account != null) {
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
  }

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

TXDB.prototype.getRangeHashes = function getRangeHashes(account, options) {
  var start, end;

  if (account && typeof account === 'object') {
    options = account;
    account = null;
  }

  start = options.start || 0;
  end = options.end || 0xffffffff;

  if (account != null) {
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
  }

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

TXDB.prototype.getUnconfirmed = co(function* getUnconfirmed(account) {
  var txs = [];
  var i, hashes, hash, tx;

  hashes = yield this.getUnconfirmedHashes(account);

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

TXDB.prototype.getCoins = function getCoins(account) {
  var self = this;

  // Slow case
  if (account != null)
    return this.getAccountCoins(account);

  // Fast case
  return this.range({
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
};

/**
 * Get coins by account.
 * @param {Number} account
 * @returns {Promise} - Returns {@link Coin}[].
 */

TXDB.prototype.getAccountCoins = co(function* getCoins(account) {
  var prevout = yield this.getOutpoints(account);
  var coins = [];
  var i, op, coin;

  for (i = 0; i < prevout.length; i++) {
    op = prevout[i];
    coin = yield this.getCoin(op.hash, op.index);

    if (!coin)
      continue;

    coins.push(coin);
  }

  return coins;
});

/**
 * Fill a transaction with coins (all historical coins).
 * @param {TX} tx
 * @returns {Promise} - Returns {@link TX}.
 */

TXDB.prototype.fillHistory = function fillHistory(tx) {
  var hash;

  if (tx.isCoinbase())
    return Promise.resolve(tx);

  hash = tx.hash('hex');

  return this.range({
    gte: layout.d(hash, 0x00000000),
    lte: layout.d(hash, 0xffffffff),
    parse: function(key, value) {
      var index = layout.dd(key)[1];
      var coin = Coin.fromRaw(value);
      var input = tx.inputs[index];
      coin.hash = input.prevout.hash;
      coin.index = input.prevout.index;
      input.coin = coin;
    }
  });
};

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

    if (coin)
      input.coin = coin;
  }

  return tx;
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
  var spent = yield this.isSpent(prevout.hash, prevout.index);
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
  var self = this;
  var balance;

  // Slow case
  if (account != null)
    return yield this.getAccountBalance(account);

  // Really fast case
  if (this.balance)
    return this.balance;

  // Fast case
  balance = new Balance(this.wallet);

  yield this.range({
    gte: layout.c(constants.NULL_HASH, 0x00000000),
    lte: layout.c(constants.HIGH_HASH, 0xffffffff),
    parse: function(key, data) {
      var parts = layout.cc(key);
      var hash = parts[0];
      var index = parts[1];
      var ckey = hash + index;
      balance.addRaw(data);
      self.coinCache.set(ckey, data);
    }
  });

  return balance;
});

/**
 * Calculate balance by account.
 * @param {Number} account
 * @returns {Promise} - Returns {@link Balance}.
 */

TXDB.prototype.getAccountBalance = co(function* getBalance(account) {
  var prevout = yield this.getOutpoints(account);
  var balance = new Balance(this.wallet);
  var i, ckey, key, coin, op, data;

  for (i = 0; i < prevout.length; i++) {
    op = prevout[i];
    ckey = op.hash + op.index;
    coin = this.coinCache.get(ckey);

    if (coin) {
      balance.addRaw(coin);
      continue;
    }

    key = layout.c(op.hash, op.index);
    data = yield this.get(key);

    if (!data)
      continue;

    balance.addRaw(data);

    this.coinCache.set(ckey, data);
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

  if (!utils.isUInt32(age))
    throw new Error('Age must be a number.');

  txs = yield this.getRange(account, {
    start: 0,
    end: now - age
  });

  for (i = 0; i < txs.length; i++) {
    tx = txs[i];
    hash = tx.hash('hex');

    if (tx.ts !== 0)
      continue;

    assert(now - tx.ps >= age);

    this.wallet.start();

    this.logger.debug('Zapping TX: %s (%s)',
      hash, this.wallet.id);

    try {
      yield this._remove(hash);
    } catch (e) {
      this.wallet.drop();
      throw e;
    }

    hashes.push(hash);

    yield this.wallet.commit();
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

function Balance(wallet) {
  if (!(this instanceof Balance))
    return new Balance(wallet);

  this.wid = wallet.wid;
  this.id = wallet.id;
  this.unconfirmed = 0;
  this.confirmed = 0;
  this.total = 0;
}

Balance.prototype.add = function add(coin) {
  this.total += coin.value;
  if (coin.height === -1)
    this.unconfirmed += coin.value;
  else
    this.confirmed += coin.value;
};

Balance.prototype.sub = function sub(coin) {
  this.total -= coin.value;
  if (coin.height === -1)
    this.unconfirmed -= coin.value;
  else
    this.confirmed -= coin.value;
};

Balance.prototype.confirm = function confirm(value) {
  this.unconfirmed -= value;
  this.confirmed += value;
};

Balance.prototype.unconfirm = function unconfirm(value) {
  this.unconfirmed += value;
  this.confirmed -= value;
};

Balance.prototype.addRaw = function addRaw(data) {
  var height = data.readUInt32LE(4, true);
  var value = utils.read64N(data, 8);

  assert(data.length >= 16);

  this.total += value;

  if (height === 0x7fffffff)
    this.unconfirmed += value;
  else
    this.confirmed += value;
};

Balance.prototype.toJSON = function toJSON() {
  return {
    wid: this.wid,
    id: this.id,
    unconfirmed: utils.btc(this.unconfirmed),
    confirmed: utils.btc(this.confirmed),
    total: utils.btc(this.total)
  };
};

Balance.prototype.toString = function toString() {
  return '<Balance'
    + ' unconfirmed=' + utils.btc(this.unconfirmed)
    + ' confirmed=' + utils.btc(this.confirmed)
    + ' total=' + utils.btc(this.total)
    + '>';
};

/*
 * Helpers
 */

function Conflict(tx, info) {
  this.tx = tx;
  this.info = info;
}

function Orphan(input, tx) {
  this.input = input;
  this.tx = tx;
}

/*
 * Expose
 */

module.exports = TXDB;
