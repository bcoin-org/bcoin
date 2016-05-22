/*!
 * walletdb.js - storage for wallets
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/indutny/bcoin
 */

/*
 * Database Layout:
 *  (inherits all from txdb)
 *  W/[address]/[id] -> dummy (map address to id)
 *  w/[id] -> wallet
 */

var bcoin = require('./env');
var EventEmitter = require('events').EventEmitter;
var utils = require('./utils');
var assert = utils.assert;
var DUMMY = new Buffer([0]);

/**
 * WalletDB
 * @exports WalletDB
 * @constructor
 * @param {Object} options
 * @param {String?} options.name - Database name.
 * @param {String?} options.location - Database file location.
 * @param {String?} options.db - Database backend (`"leveldb"` by default).
 * @param {Boolean?} options.verify - Verify transactions as they
 * come in (note that this will not happen on the worker pool).
 * @property {Boolean} loaded
 */

function WalletDB(options) {
  if (!(this instanceof WalletDB))
    return new WalletDB(options);

  if (!options)
    options = {};

  EventEmitter.call(this);

  this.options = options;
  this.loaded = false;
  this.network = bcoin.network.get(options.network);

  this._init();
}

utils.inherits(WalletDB, EventEmitter);

/**
 * Dump database (for debugging).
 * @param {Function} callback - Returns [Error, Object].
 */

WalletDB.prototype.dump = function dump(callback) {
  var records = {};

  var iter = this.db.iterator({
    gte: 'w',
    lte: 'w~',
    keys: true,
    values: true,
    fillCache: false,
    keyAsBuffer: false,
    valueAsBuffer: true
  });

  callback = utils.ensure(callback);

  (function next() {
    iter.next(function(err, key, value) {
      if (err) {
        return iter.end(function() {
          callback(err);
        });
      }

      if (key === undefined) {
        return iter.end(function(err) {
          if (err)
            return callback(err);
          return callback(null, records);
        });
      }

      records[key] = value;

      next();
    });
  })();
};

WalletDB.prototype._init = function _init() {
  var self = this;

  if (this.loaded)
    return;

  this.db = bcoin.ldb({
    network: this.network,
    name: this.options.name || 'wallet',
    location: this.options.location,
    db: this.options.db,
    cacheSize: 8 << 20,
    writeBufferSize: 4 << 20
  });

  this.tx = new bcoin.txdb(this.db, {
    network: this.network,
    indexExtra: true,
    indexAddress: true,
    mapAddress: true,
    verify: this.options.verify,
    useFilter: true
  });

  this.db.open(function(err) {
    if (err)
      return self.emit('error', err);

    self.tx._loadFilter(function(err) {
      if (err)
        return self.emit('error', err);

      self.emit('open');
      self.loaded = true;
    });
  });

  this.tx.on('error', function(err) {
    self.emit('error', err);
  });

  this.tx.on('tx', function(tx, map) {
    self.emit('tx', tx, map);
    map.all.forEach(function(id) {
      self.emit(id + ' tx', tx);
    });
  });

  this.tx.on('confirmed', function(tx, map) {
    self.emit('confirmed', tx, map);
    map.all.forEach(function(id) {
      self.emit(id + ' confirmed', tx);
    });
    utils.forEachSerial(map.output, function(id, next) {
      self.syncOutputDepth(id, tx, next);
    }, function(err) {
      if (err)
        self.emit('error', err);
    });
  });

  this.tx.on('unconfirmed', function(tx, map) {
    self.emit('unconfirmed', tx, map);
    map.all.forEach(function(id) {
      self.emit(id + ' unconfirmed', tx);
    });
  });

  this.tx.on('updated', function(tx, map) {
    var balances = {};

    self.emit('updated', tx, map);
    map.all.forEach(function(id) {
      self.emit(id + ' updated', tx);
    });

    utils.forEachSerial(map.output, function(id, next) {
      if (self.listeners('balance').length === 0
          && self.listeners(id + ' balance').length === 0) {
        return next();
      }

      self.getBalance(id, function(err, balance) {
        if (err)
          return next(err);

        balances[id] = balance;

        self.emit('balance', balance, id);
        self.emit(id + ' balance', balance);

        next();
      });
    }, function(err) {
      if (err)
        return self.emit('error', err);

      self.emit('balances', balances, map);
    });
  });
};

/**
 * Open the walletdb, wait for the database to load.
 * @param {Function} callback
 */

WalletDB.prototype.open = function open(callback) {
  if (this.loaded)
    return utils.nextTick(callback);

  this.once('open', callback);
};

/**
 * Close the walletdb, wait for the database to close.
 * @method
 * @param {Function} callback
 */

WalletDB.prototype.close =
WalletDB.prototype.destroy = function destroy(callback) {
  callback = utils.ensure(callback);
  this.db.close(callback);
};

/**
 * Sync address depths based on a transaction's outputs.
 * This is used for deriving new addresses when
 * a confirmed transaction is seen.
 * @param {WalletID} id
 * @param {TX} tx
 * @param {Function} callback
 */

WalletDB.prototype.syncOutputDepth = function syncOutputDepth(id, tx, callback) {
  var self = this;

  callback = utils.ensure(callback);

  this.getJSON(id, function(err, json) {
    if (err)
      return callback(err);

    // Allocate new addresses if necessary.
    json = bcoin.wallet.syncOutputDepth(json, tx);

    if (!json)
      return callback();

    self.saveJSON(id, json, function(err) {
      if (err)
        return callback(err);

      self.emit('sync output depth', id, tx);

      callback();
    });
  });
};

/**
 * Set receiving/change depth (depth is the index of the _next_ address).
 * Allocate all addresses up to depth. Note that this also allocates
 * new lookahead addresses.
 * @param {WalletID} id
 * @param {Number} receive - Receive address depth.
 * @param {Number} change - Change address depth.
 * @param {Function} callback
 */

WalletDB.prototype.setDepth = function setDepth(id, receive, change, callback) {
  var self = this;

  callback = utils.ensure(callback);

  this.getJSON(id, function(err, json) {
    if (err)
      return callback(err);

    // Allocate new addresses if necessary.
    json = bcoin.wallet.setDepth(json, receive, change);

    if (!json)
      return callback();

    self.saveJSON(id, json, function(err) {
      if (err)
        return callback(err);

      self.emit('set depth', id, receive, change);

      callback();
    });
  });
};

/**
 * Add a public account/purpose key to the wallet for multisig.
 * @param {WalletID} id
 * @param {HDPublicKey|Base58String} key - Account (bip44) or
 * Purpose (bip45) key (can be in base58 form).
 * @param {Function} callback
 */

WalletDB.prototype.addKey = function addKey(id, key, callback) {
  var self = this;

  callback = utils.ensure(callback);

  this.getJSON(id, function(err, json) {
    if (err)
      return callback(err);

    try {
      json = bcoin.wallet.addKey(json, key);
    } catch (e) {
      return callback(e);
    }

    self.saveJSON(id, json, callback);
  });
};

/**
 * Remove a public account/purpose key to the wallet for multisig.
 * @param {WalletID} id
 * @param {HDPublicKey|Base58String} key - Account (bip44) or Purpose
 * (bip45) key (can be in base58 form).
 * @param {Function} callback
 */

WalletDB.prototype.removeKey = function removeKey(id, key, callback) {
  var self = this;

  callback = utils.ensure(callback);

  this.getJSON(id, function(err, json) {
    if (err)
      return callback(err);

    try {
      json = bcoin.wallet.removeKey(json, key);
    } catch (e) {
      return callback(e);
    }

    self.saveJSON(id, json, callback);
  });
};

/**
 * Retrieve wallet without instantiating it.
 * @param {WalletID} id
 * @param {Function} callback - Returns [Error, Object(nakedWallet)].
 */

WalletDB.prototype.getJSON = function getJSON(id, callback) {
  if (typeof id === 'object')
    id = id.id;

  callback = utils.ensure(callback);

  return this._getDB(id, callback);
};

/**
 * Save a "naked" (non-instantiated) wallet. Will
 * also index the address table.
 * @param {WalletID}
 * @param {Object} json - "Naked" wallet.
 * @param {Function} callback - Returns [Error, Object].
 */

WalletDB.prototype.saveJSON = function saveJSON(id, json, callback) {
  var self = this;

  callback = utils.ensure(callback);

  return this._saveDB(id, json, function(err, json) {
    var batch;

    if (err)
      return callback(err);

    if (json) {
      batch = self.db.batch();

      Object.keys(json.addressMap).forEach(function(address) {
        if (self.tx.filter)
          self.tx.filter.add(address, 'hex');

        batch.put('W/' + address + '/' + json.id, DUMMY);
      });

      return batch.write(function(err) {
        if (err)
          return callback(err);
        return callback(null, json);
      });
    }

    return callback(null, json);
  });
};

/**
 * Remove wallet from the database.
 * @param {WalletID} id
 * @param {Function} callback - Returns [Error, Object].
 */

WalletDB.prototype.removeJSON = function removeJSON(id, callback) {
  var self = this;

  callback = utils.ensure(callback);

  if (typeof id === 'object')
    id = id.id;

  return this._removeDB(id, function(err, json) {
    var batch;

    if (err)
      return callback(err);

    if (json) {
      batch = self.db.batch();
      Object.keys(json.addressMap).forEach(function(address) {
        batch.del('W/' + address + '/' + json.id);
      });
      return batch.write(function(err) {
        if (err)
          return callback(err);
        return callback(null, json);
      });
    }

    return callback(null, json);
  });
};

/**
 * Retrieve object from the database.
 * @private
 * @param {WalletID} id
 * @param {Function} callback - Returns [Error, Object(nakedWallet)].
 */

WalletDB.prototype._getDB = function _getDB(id, callback) {
  var key = 'w/' + id;

  callback = utils.ensure(callback);

  this.db.get(key, function(err, json) {
    if (err && err.type === 'NotFoundError')
      return callback();

    if (err)
      return callback(err);

    try {
      json = JSON.parse(json.toString('utf8'));
    } catch (e) {
      return callback(e);
    }

    return callback(null, json);
  });
};

/**
 * Save object to the database.
 * @private
 * @param {WalletID} id
 * @param {Object} json
 * @param {Function} callback - Returns [Error, nakedWallet].
 */

WalletDB.prototype._saveDB = function _saveDB(id, json, callback) {
  var key = 'w/' + id;
  var data;

  callback = utils.ensure(callback);

  data = new Buffer(JSON.stringify(json), 'utf8');

  this.db.put(key, data, function(err) {
    if (err)
      return callback(err);

    return callback(null, json);
  });
};

/**
 * Remove object from the database.
 * @private
 * @param {WalletID} id
 * @param {Function} callback - Returns [Error, Object].
 */

WalletDB.prototype._removeDB = function _removeDB(id, callback) {
  var self = this;
  var key = 'w/' + id;

  callback = utils.ensure(callback);

  this._getDB(id, function(err, json) {
    if (err)
      return callback(err);

    self.db.del(key, function(err) {
      if (err && err.type !== 'NotFoundError')
        return callback(err);

      return callback(null, json);
    });
  });
};

/**
 * Get a wallet from the database, instantiate, decrypt, and setup provider.
 * @param {WalletID} id
 * @param {String?} passphrase
 * @param {Function} callback - Returns [Error, {@link Wallet}].
 */

WalletDB.prototype.get = function get(id, passphrase, callback) {
  var self = this;

  if (typeof passphrase === 'function') {
    callback = passphrase;
    passphrase = null;
  }

  callback = utils.ensure(callback);

  return this.getJSON(id, function(err, options) {
    var wallet;

    if (err)
      return callback(err);

    if (!options)
      return callback();

    try {
      options = bcoin.wallet.parseJSON(options, passphrase);
      options.provider = new Provider(self);
      wallet = new bcoin.wallet(options);
    } catch (e) {
      return callback(e);
    }

    return callback(null, wallet);
  });
};

/**
 * Save a wallet to the database (setup ida and encrypt).
 * @param {WalletID?} id
 * @param {Wallet} options
 * @param {Function} callback
 */

WalletDB.prototype.save = function save(id, options, callback) {
  if (id && typeof id === 'object') {
    callback = options;
    options = id;
    id = null;
  }

  if (!id)
    id = options.id;
  else
    options.id = id;

  callback = utils.ensure(callback);

  assert(options instanceof bcoin.wallet);
  options = options.toJSON();

  this.saveJSON(id, options, callback);
};

/**
 * Remove wallet from the database. Destroy wallet if passed in.
 * @param {WalletID|Wallet} id
 * @param {Function} callback
 */

WalletDB.prototype.remove = function remove(id, callback) {
  if (id instanceof bcoin.wallet)
    id.destroy();

  if (id && id.id)
    id = id.id;

  callback = utils.ensure(callback);

  return this.removeJSON(id, callback);
};

/**
 * Create a new wallet, save to database, setup provider.
 * @param {WalletID?} id
 * @param {Object} options - See {@link Wallet}.
 * @param {Function} callback - Returns [Error, {@link Wallet}].
 */

WalletDB.prototype.create = function create(id, options, callback) {
  var self = this;

  if (id && typeof id === 'object') {
    callback = options;
    options = id;
    id = null;
  }

  if (!id)
    id = options.id;
  else
    options.id = id;

  callback = utils.ensure(callback);

  function create(err, json) {
    var wallet;

    if (err)
      return callback(err);

    if (json)
      return callback(new Error('`' + id + '` already exists.'), null, json);

    if (self.network.witness)
      options.witness = options.witness !== false;

    options.provider = new Provider(self);
    options.network = self.network;
    wallet = new bcoin.wallet(options);

    self.saveJSON(wallet.id, wallet.toJSON(), function(err) {
      if (err)
        return callback(err);

      return callback(null, wallet);
    });
  }

  if (!id)
    return create();

  return this.getJSON(id, create);
};

/**
 * Attempt to create wallet, return wallet if already exists.
 * @param {WalletID?} id
 * @param {Object} options - See {@link Wallet}.
 * @param {Function} callback
 */

WalletDB.prototype.ensure = function ensure(id, options, callback) {
  var self = this;

  if (id && typeof id === 'object') {
    callback = options;
    options = id;
    id = null;
  }

  if (!id)
    id = options.id;
  else
    options.id = id;

  callback = utils.ensure(callback);

  return this.create(id, options, function(err, wallet, json) {
    if (err && !json)
      return callback(err);

    if (wallet)
      return callback(null, wallet);

    assert(json);

    try {
      options = bcoin.wallet.parseJSON(json, options.passphrase);
      options.provider = new Provider(self);
      wallet = new bcoin.wallet(options);
    } catch (e) {
      return callback(e);
    }

    return callback(null, wallet);
  });
};

/**
 * Notify the database that a new address
 * has been derived. Save to address table. Save wallet.
 * @param {Wallet} wallet
 * @param {Address} address
 */

WalletDB.prototype.update = function update(wallet, address) {
  var self = this;
  var batch;

  // Ugly hack to avoid extra writes.
  if (!wallet.changeAddress && wallet.changeDepth > 1)
    return;

  batch = this.db.batch();

  batch.put(
    'W/' + address.getKeyHash('hex') + '/' + wallet.id,
    DUMMY);

  if (this.tx.filter)
    this.tx.filter.add(address.getKeyHash());

  if (address.type === 'multisig') {
    batch.put(
      'W/' + address.getScriptHash('hex') + '/' + wallet.id,
      DUMMY);

    if (this.tx.filter)
      this.tx.filter.add(address.getScriptHash());
  }

  if (address.witness) {
    batch.put(
      'W/' + address.getProgramHash('hex') + '/' + wallet.id,
      DUMMY);

    if (this.tx.filter)
      this.tx.filter.add(address.getProgramHash());
  }

  batch.write(function(err) {
    if (err)
      self.emit('error', err);

    // XXX might have to encrypt key - slow
    self._saveDB(wallet.id, wallet.toJSON(), function(err) {
      if (err)
        self.emit('error', err);
    });
  });
};

/**
 * @see {@link TXDB#add}.
 */

WalletDB.prototype.addTX = function addTX(tx, callback) {
  return this.tx.add(tx, callback);
};

/**
 * @see {@link TXDB#getTX}.
 */

WalletDB.prototype.getTX = function getTX(hash, callback) {
  return this.tx.getTX(hash, callback);
};

/**
 * @see {@link TXDB#getCoin}.
 */

WalletDB.prototype.getCoin = function getCoin(hash, index, callback) {
  return this.tx.getCoin(hash, index, callback);
};

/**
 * @see {@link TXDB#getHistoryByAddress}.
 */

WalletDB.prototype.getHistory = function getHistory(id, callback) {
  id = id.id || id;
  return this.tx.getHistoryByAddress(id, callback);
};

/**
 * @see {@link TXDB#getCoinsByAddress}.
 */

WalletDB.prototype.getCoins = function getCoins(id, callback) {
  id = id.id || id;
  return this.tx.getCoinsByAddress(id, callback);
};

/**
 * @see {@link TXDB#getUnconfirmedByAddress}.
 */

WalletDB.prototype.getUnconfirmed = function getUnconfirmed(id, callback) {
  id = id.id || id;
  return this.tx.getUnconfirmedByAddress(id, callback);
};

/**
 * @see {@link TXDB#getBalanceByAddress}.
 */

WalletDB.prototype.getBalance = function getBalance(id, callback) {
  id = id.id || id;
  return this.tx.getBalanceByAddress(id, callback);
};

/**
 * @see {@link TXDB#getLastTime}.
 */

WalletDB.prototype.getLastTime = function getLastTime(id, callback) {
  id = id.id || id;
  return this.tx.getLastTime(id, callback);
};

/**
 * @see {@link TXDB#getLast}.
 */

WalletDB.prototype.getLast = function getLast(id, limit, callback) {
  id = id.id || id;
  return this.tx.getLast(id, limit, callback);
};

/**
 * @see {@link TXDB#getRange}.
 */

WalletDB.prototype.getRange = function getRange(id, options, callback) {
  id = id.id || id;
  return this.tx.getRange(id, options, callback);
};

/**
 * @see {@link TXDB#fillHistory}.
 */

WalletDB.prototype.fillHistory = function fillHistory(tx, callback) {
  return this.tx.fillHistory(tx, callback);
};

/**
 * @see {@link TXDB#fillCoins}.
 */

WalletDB.prototype.fillCoins = function fillCoins(tx, callback) {
  return this.tx.fillCoins(tx, callback);
};

/**
 * Notify the database that a block has been
 * removed (reorg). Unconfirms transactions by height.
 * @param {MerkleBlock|Block} block
 * @param {Function} callback
 */

WalletDB.prototype.removeBlockSPV = function removeBlockSPV(block, callback) {
  var self = this;

  callback = utils.ensure(callback);

  this.tx.getHeightHashes(block.height, function(err, txs) {
    if (err)
      return callback(err);

    utils.forEachSerial(txs, function(tx, next) {
      self.tx.unconfirm(tx, next);
    }, callback);
  });
};

/**
 * Notify the database that a block has been
 * removed (reorg). Unconfirms transactions.
 * @param {Block} block
 * @param {Function} callback
 */

WalletDB.prototype.removeBlock = function removeBlock(block, callback) {
  var self = this;

  callback = utils.ensure(callback);

  utils.forEachSerial(block.txs, function(tx, next) {
    self.tx.unconfirm(tx.hash('hex'), next);
  }, callback);
};

/**
 * Zap all walletdb transactions.
 * @see {@link TXDB#zap}.
 */

WalletDB.prototype.zap = function zap(now, age, callback) {
  return this.tx.zap(now, age, callback);
};

/**
 * Zap transactions for wallet.
 * @see {@link TXDB#zap}.
 */

WalletDB.prototype.zapWallet = function zapWallet(id, now, age, callback) {
  id = id.id || id;
  return this.tx.zap(id, now, age, callback);
};

/**
 * Instantiate a {@link Provider}.
 * @returns {Provider}
 */

WalletDB.prototype.provider = function provider() {
  return new Provider(this);
};

/**
 * Represents {@link Wallet} Provider. This is what
 * allows the {@link Wallet} object to access
 * transactions and utxos, as well as listen for
 * events like confirmations, etc. Any object that
 * follows this model can be used as a wallet provider.
 * @exports Provider
 * @constructor
 * @param {WalletDB} db
 * @property {WalletDB} db
 * @property {WalletID?} id
 */

function Provider(db) {
  if (!(this instanceof Provider))
    return new Provider(db);

  EventEmitter.call(this);

  this.loaded = false;
  this.db = db;
  this.id = null;

  this._init();
}

utils.inherits(Provider, EventEmitter);

Provider.prototype._init = function _init() {
  var self = this;

  if (this.db.loaded) {
    this.loaded = true;
    return;
  }

  this.db.once('open', function() {
    self.loaded = true;
    self.emit('open');
  });
};

/**
 * Open the provider, wait for the database to load.
 * @param {Function} callback
 */

Provider.prototype.open = function open(callback) {
  return this.db.open(callback);
};

/**
 * Set the ID, telling the provider backend
 * which wallet we want to listen for events on.
 * @param {WalletID}
 */

Provider.prototype.setID = function setID(id) {
  var self = this;

  assert(!this.id, 'ID has already been set.');

  this.id = id;

  this.db.on(id + ' tx', this._onTX = function(tx) {
    self.emit('tx', tx);
  });

  this.db.on(id + ' updated', this._onUpdated = function(tx) {
    self.emit('updated', tx);
  });

  this.db.on(id + ' confirmed', this._onConfirmed = function(tx) {
    self.emit('confirmed', tx);
  });

  this.db.on(id + ' unconfirmed', this._onUnconfirmed = function(tx) {
    self.emit('unconfirmed', tx);
  });

  this.db.on(id + ' balance', this._onBalance = function(balance) {
    self.emit('balance', balance);
  });
};

/**
 * Close the provider, unlisten on wallet.
 * @method
 * @param {Function} callback
 */

Provider.prototype.close =
Provider.prototype.destroy = function destroy(callback) {
  callback = utils.ensure(callback);

  if (!this.db)
    return utils.nextTick(callback);

  if (this._onTX) {
    this.db.removeListener(this.id + ' tx', this._onTX);
    delete this._onTX;
  }

  if (this._onUpdated) {
    this.db.removeListener(this.id + ' updated', this._onUpdated);
    delete this._onUpdated;
  }

  if (this._onConfirmed) {
    this.db.removeListener(this.id + ' confirmed', this._onConfirmed);
    delete this._onConfirmed;
  }

  if (this._onUnconfirmed) {
    this.db.removeListener(this.id + ' unconfirmed', this._onUnconfirmed);
    delete this._onUnconfirmed;
  }

  if (this._onBalance) {
    this.db.removeListener(this.id + ' balance', this._onBalance);
    delete this._onBalance;
  }

  this.db = null;

  return utils.nextTick(callback);
};

/**
 * Get all transactions for wallet.
 * @param {Function} callback - Returns [Error, {@link TX}[]].
 */

Provider.prototype.getHistory = function getHistory(callback) {
  return this.db.getHistory(this.id, callback);
};

/**
 * Get all coins for wallet.
 * @param {Function} callback - Returns [Error, {@link Coin}[]].
 */

Provider.prototype.getCoins = function getCoins(callback) {
  return this.db.getCoins(this.id, callback);
};

/**
 * Get all unconfirmed transactions for wallet.
 * @param {Function} callback - Returns [Error, {@link TX}[]].
 */

Provider.prototype.getUnconfirmed = function getUnconfirmed(callback) {
  return this.db.getUnconfirmed(this.id, callback);
};

/**
 * Calculate wallet balance.
 * @param {Function} callback - Returns [Error, {@link Balance}].
 */

Provider.prototype.getBalance = function getBalance(callback) {
  return this.db.getBalance(this.id, callback);
};

/**
 * Get last active timestamp and height.
 * @param {Function} callback - Returns [Error, Number(ts), Number(height)].
 */

Provider.prototype.getLastTime = function getLastTime(callback) {
  return this.db.getLastTime(this.id, callback);
};

/**
 * Get last N transactions.
 * @param {Number} limit - Max number of transactions.
 * @param {Function} callback - Returns [Error, {@link TX}[]].
 */

Provider.prototype.getLast = function getLast(limit, callback) {
  return this.db.getLast(this.id, limit, callback);
};

/**
 * Get transactions by timestamp range.
 * @param {Object} options
 * @param {Number} options.start - Start time.
 * @param {Number} options.end - End time.
 * @param {Number?} options.limit - Max number of records.
 * @param {Boolean?} options.reverse - Reverse order.
 * @param {Function} callback - Returns [Error, {@link TX}[]].
 */

Provider.prototype.getRange = function getRange(options, callback) {
  return this.db.getRange(this.id, options, callback);
};

/**
 * Get transaction.
 * @param {Hash} hash
 * @param {Function} callback - Returns [Error, {@link TX}].
 */

Provider.prototype.getTX = function getTX(hash, callback) {
  return this.db.getTX(hash, callback);
};

/**
 * Get coin.
 * @param {Hash} hash
 * @param {Number} index
 * @param {Function} callback - Returns [Error, {@link Coin}].
 */

Provider.prototype.getCoin = function getCoin(hash, index, callback) {
  return this.db.getCoin(hash, index, callback);
};

/**
 * Fill a transaction with coins (all historical coins).
 * @param {TX} tx
 * @param {Function} callback - Returns [Error, {@link TX}].
 */

Provider.prototype.fillHistory = function fillHistory(tx, callback) {
  return this.db.fillHistory(tx, callback);
};

/**
 * Fill a transaction with coins.
 * @param {TX} tx
 * @param {Function} callback - Returns [Error, {@link TX}].
 */

Provider.prototype.fillCoins = function fillCoins(tx, callback) {
  return this.db.fillCoins(tx, callback);
};

/**
 * Add a transaction to the provider backend (not
 * technically necessary if you're implementing a provider).
 * @param {TX} tx
 * @param {Function} callback
 */

Provider.prototype.addTX = function addTX(tx, callback) {
  return this.db.tx.add(tx, callback);
};

/**
 * Notify the provider backend that a new address was
 * derived (not technically necessary if you're
 * implementing a provider).
 * @param {Wallet} wallet
 * @param {Address} address
 */

Provider.prototype.update = function update(wallet, address) {
  return this.db.update(wallet, address);
};

/**
 * Zap stale transactions.
 * @param {Number} now - Current time.
 * @param {Number} age - Age delta (delete transactions older than `now - age`).
 * @param {Function} callback
 */

Provider.prototype.zap = function zap(now, age, callback) {
  return this.db.zapWallet(this.id, now, age, callback);
};

/*
 * Expose
 */

exports = WalletDB;

exports.Provider = Provider;

module.exports = exports;
