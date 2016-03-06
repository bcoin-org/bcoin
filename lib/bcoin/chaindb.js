/**
 * chaindb.js - blockchain data management for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var EventEmitter = require('events').EventEmitter;

var bcoin = require('../bcoin');
var bn = require('bn.js');
var constants = bcoin.protocol.constants;
var network = bcoin.protocol.network;
var utils = bcoin.utils;
var assert = utils.assert;
var pad32 = utils.pad32;

/**
 * ChainDB
 */

function ChainDB(node, chain, options) {
  if (!(this instanceof ChainDB))
    return new ChainDB(node, chain, options);

  if (!options)
    options = {};

  EventEmitter.call(this);

  this.options = options;
  this.node = node;
  this.network = node.network;
  this.chain = chain;
  this.file = options.file;

  if (!this.file) {
    this.file = bcoin.prefix
      + '/chain-'
      + (options.spv ? 'spv-' : '')
      + network.type
      + '.db';
  }

  this.queue = {};
  this.queueSize = 0;
  this.size = 0;
  this.fd = null;
  this.loading = false;
  this.loaded = false;

  // Keep track of block hashes in a
  // bloom filter to avoid DB lookups.
  // 1% false positive rate for 800k blocks
  // http://hur.st/bloomfilter?n=800000&p=0.01 (m=936kb, k=7)
  // 10% false positive rate for 800k blocks
  // http://hur.st/bloomfilter?n=800000&p=0.10 (m=468kb, k=3)
  // this.bloom = new bcoin.bloom(937 * 1024, 7, 0xdeadbeef);

  // Need to cache up to the retarget interval
  // if we're going to be checking the damn
  // target all the time.
  if (network.powAllowMinDifficultyBlocks)
    this._cacheWindow = network.powDiffInterval + 1;
  else
    this._cacheWindow = network.block.majorityWindow + 1;

  this.cacheHash = new DumbCache(this._cacheWindow * 200); // (not hashcash)
  this.cacheHeight = new DumbCache(this._cacheWindow * 200);
  // this.cacheHash = new bcoin.lru(this._cacheWindow, function() { return 1; }); // (not hashcash)
  // this.cacheHeight = new bcoin.lru(this._cacheWindow, function() { return 1; });

  this._init();
}

utils.inherits(ChainDB, EventEmitter);

ChainDB.prototype._init = function _init() {
  var levelup = require('levelup');

  bcoin.ensurePrefix();

  if (+process.env.BCOIN_FRESH === 1 && bcoin.cp)
    bcoin.cp.execFileSync('rm', ['-rf', this.file], { stdio: 'ignore' });

  this.db = new levelup(this.file, {
    keyEncoding: 'ascii',
    valueEncoding: 'binary',
    createIfMissing: true,
    errorIfExists: false,
    compression: false,
    cacheSize: 16 * 1024 * 1024,
    writeBufferSize: 8 * 1024 * 1024,
    // blockSize: 4 * 1024,
    maxOpenFiles: 8192,
    // blockRestartInterval: 16,
    db: bcoin.isBrowser
      ? require('level-js')
      : require('level' + 'down')
  });
};

ChainDB.prototype.load = function load(callback) {
  var self = this;

  var genesis = bcoin.chainblock.fromJSON(this.chain, {
    hash: network.genesis.hash,
    version: network.genesis.version,
    prevBlock: network.genesis.prevBlock,
    merkleRoot: network.genesis.merkleRoot,
    ts: network.genesis.ts,
    bits: network.genesis.bits,
    nonce: network.genesis.nonce,
    height: 0
  });

  this.loading = true;

  utils.debug('Starting chain load.');

  function finish(err) {
    if (err)
      return callback(err);

    self.loading = false;
    self.loaded = true;
    self.emit('load');

    utils.debug('Chain successfully loaded.');

    callback();
  }

  this.db.get('c/b/' + genesis.hash, function(err, exists) {
    if (err && err.type !== 'NotFoundError')
      throw err;

    if (!exists)
      self.save(genesis, finish);
    else
      finish();
  });
};

ChainDB.prototype.close = function close(callback) {
  callback = utils.ensure(callback);
  this.db.close(callback);
};

ChainDB.prototype.addCache = function addCache(entry) {
  this.cacheHash.set(entry.hash, entry);
  this.cacheHeight.set(entry.height, entry);
};

ChainDB.prototype.hasCache = function hasCache(hash) {
  if (hash == null || hash < 0)
    return false;

  if (typeof hash === 'number')
    return this.cacheHeight.has(hash);

  return this.cacheHash.has(hash);
};

ChainDB.prototype.getCache = function getCache(hash) {
  if (hash == null || hash < 0)
    return;

  if (typeof hash === 'number')
    return this.cacheHeight.get(hash);

  return this.cacheHash.get(hash);
};

ChainDB.prototype.getHeight = function getHeight(hash, callback) {
  if (hash == null || hash < 0)
    return callback(null, -1);

  if (typeof hash === 'number')
    return callback(null, hash);

  // When prevBlock=zero-hash
  if (+hash === 0)
    return callback(null, -1);

  if (this.cacheHash.has(hash))
    return callback(null, this.cacheHash.get(hash).height);

  // if (!this.bloom.test(hash, 'hex'))
  //   return callback(null, -1);

  this.db.get('c/b/' + hash, function(err, height) {
    if (err && err.type !== 'NotFoundError')
      return callback(err);

    if (height == null)
      return callback(null, -1);

    return callback(null, utils.readU32(height, 0));
  });
};

ChainDB.prototype.getHash = function getHash(height, callback) {
  if (height == null || height < 0)
    return callback(null, null);

  if (typeof height === 'string')
    return callback(null, height);

  if (this.cacheHeight.has(height))
    return callback(null, this.cacheHeight.get(height).hash);

  this.db.get('c/h/' + pad32(height), function(err, hash) {
    if (err && err.type !== 'NotFoundError')
      return callback(err);

    if (hash == null)
      return callback(null, null);

    return callback(null, utils.toHex(hash));
  });
};

ChainDB.prototype.dump = function dump(callback) {
  var self = this;
  var records = {};

  var iter = this.db.db.iterator({
    gte: 'c',
    lte: 'c~',
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

ChainDB.prototype.getChainHeight = function getChainHeight(callback) {
  return this.getTip(function(err, entry) {
    if (err)
      return callback(err);

    if (!entry)
      return callback(null, -1);

    return callback(null, entry.height);
  });
};

ChainDB.prototype.getBoth = function getBoth(block, callback) {
  var hash, height;

  if (block == null || block < 0)
    return callback(null, null, -1);

  if (typeof block === 'string')
    hash = block;
  else
    height = block;

  if (!hash) {
    return this.getHash(height, function(err, hash) {
      if (err)
        return callback(err);

      if (hash == null)
        height = -1;

      return callback(null, hash, height);
    });
  }

  return this.getHeight(hash, function(err, height) {
    if (err)
      return callback(err);

    if (height === -1)
      hash = null;

    return callback(null, hash, height);
  });
};

ChainDB.prototype.getEntry = function getEntry(hash, callback) {
  var self = this;
  var entry;

  if (hash == null || hash < 0)
    return callback();

  return this.getBoth(hash, function(err, hash, height) {
    if (err && err.type !== 'NotFoundError')
      return callback(err);

    if (!hash)
      return callback();

    if (self.cacheHash.has(hash))
      return callback(null, self.cacheHash.get(hash));

    return self.db.get('c/c/' + hash, function(err, data) {
      if (err && err.type !== 'NotFoundError')
        return callback(err);

      if (!data)
        return callback();

      entry = bcoin.chainblock.fromRaw(self.chain, data);

      return callback(null, entry);
    });
  });
};

ChainDB.prototype.get = function get(height, callback, force) {
  var self = this;

  callback = utils.asyncify(callback);

  return this.getEntry(height, function(err, entry) {
    if (err)
      return callback(err);

    if (!entry)
      return callback();

    // Cache the past 1001 blocks in memory
    // (necessary for isSuperMajority)
    self.addCache(entry);

    return callback(null, entry);
  });
};

ChainDB.prototype.save = function save(entry, callback) {
  var self = this;
  var batch, height;

  callback = utils.asyncify(callback);

  assert(entry.height >= 0);

  // Cache the past 1001 blocks in memory
  // (necessary for isSuperMajority)
  this.addCache(entry);

  // this.bloom.add(entry.hash, 'hex');

  batch = this.db.batch();
  height = new Buffer(4);
  utils.writeU32(height, entry.height, 0);

  batch.put('c/h/' + pad32(entry.height), new Buffer(entry.hash, 'hex'));
  batch.put('c/b/' + entry.hash, height);
  batch.put('c/c/' + entry.hash, entry.toRaw());
  batch.put('c/n/' + entry.prevBlock, new Buffer(entry.hash, 'hex'));
  batch.put('c/t', new Buffer(entry.hash, 'hex'));

  return batch.write(function(err) {
    if (err)
      return callback(err);

    return callback(null, true);
  });
};

ChainDB.prototype.getTip = function getTip(callback) {
  var self = this;
  return this.db.get('c/t', function(err, hash) {
    if (err && err.type !== 'NotFoundError')
      return callback(err);

    if (!hash)
      return callback();

    return self.get(utils.toHex(hash), callback);
  });
};

ChainDB.prototype.connect = function connect(block, callback, emit) {
  var self = this;
  var batch;

  this._get(block, function(err, entry) {
    if (err)
      return callback(err);

    if (!entry)
      return callback();

    batch = self.db.batch();

    batch.put('c/h/' + pad32(entry.height), new Buffer(entry.hash, 'hex'));
    batch.put('c/t', new Buffer(entry.hash, 'hex'));

    self.cacheHeight.set(entry.height, entry);

    batch.write(function(err) {
      if (err)
        return callback(err);
      return callback(null, entry);
    });
  });
};

ChainDB.prototype.disconnect = function disconnect(block, callback) {
  var self = this;
  var batch;

  this._get(block, function(err, entry) {
    if (err)
      return callback(err);

    if (!entry)
      return callback();

    batch = self.db.batch();

    batch.del('c/h/' + pad32(entry.height));
    batch.put('c/t', new Buffer(entry.prevBlock, 'hex'));

    self.cacheHeight.remove(entry.height);

    batch.write(function(err) {
      if (err)
        return callback(err);
      return callback(null, entry);
    });
  });
};

ChainDB.prototype._get = function _get(block, callback) {
  if (block instanceof bcoin.chainblock)
    return callback(null, block);
  return this.get(block, callback);
};

ChainDB.prototype.getNextHash = function getNextHash(hash, callback) {
  return this.db.get('c/n/' + hash, function(err, nextHash) {
    if (err && err.type !== 'NotFoundError')
      return callback(err);

    if (!nextHash)
      return callback();

    return callback(null, utils.toHex(nextHash));
  });
};

ChainDB.prototype.reset = function reset(block, callback, emit) {
  var self = this;
  var batch;

  this.get(block, function(err, entry) {
    if (err)
      return callback(err);

    if (!entry)
      return callback();

    self.getTip(function(err, tip) {
      if (err)
        return callback(err);

      if (!tip)
        return callback();

      batch = self.db.batch();

      (function next(err, tip) {
        if (err)
          return done(err);

        if (!tip)
          return done();

        if (tip.hash === entry.hash) {
          batch.put('c/t', new Buffer(tip.hash, 'hex'));
          return batch.write(callback);
        }

        batch.del('c/h/' + pad32(tip.height));
        batch.del('c/b/' + tip.hash);
        batch.del('c/c/' + tip.hash);
        batch.del('c/n/' + tip.prevBlock);

        if (emit)
          emit(tip);

        self.get(tip.prevBlock, next);
      })(null, tip);
    });
  });
};

ChainDB.prototype.has = function has(height, callback) {
  if (height == null || height < 0)
    return callback(null, false);

  return this.getBoth(height, function(err, hash, height) {
    if (err)
      return callback(err);
    return callback(null, hash != null);
  });
};

function DumbCache(size) {
  this.data = {};
  this.count = 0;
  this.size = size;
}

DumbCache.prototype.set = function set(key, value) {
  key = key + '';

  assert(value !== undefined);

  if (this.count > this.size)
    this.reset();

  if (this.data[key] === undefined)
    this.count++;

  this.data[key] = value;
};

DumbCache.prototype.remove = function remove(key) {
  key = key + '';

  if (this.data[key] === undefined)
    return;

  this.count--;
  delete this.data[key];
};

DumbCache.prototype.get = function get(key) {
  key = key + '';
  return this.data[key];
};

DumbCache.prototype.has = function has(key) {
  key = key + '';
  return this.data[key] !== undefined;
};

DumbCache.prototype.reset = function reset() {
  this.data = {};
  this.count = 0;
};

/**
 * Expose
 */

module.exports = ChainDB;
