/**
 * walletdb.js - storage for wallets
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var inherits = require('inherits');
var EventEmitter = require('events').EventEmitter;

var bcoin = require('../bcoin');
var levelup = require('levelup');
var bn = require('bn.js');
var constants = bcoin.protocol.constants;
var network = bcoin.protocol.network;
var utils = bcoin.utils;
var assert = utils.assert;
var fs = bcoin.fs;

/**
 * WalletDB
 */

function WalletDB(options) {
  if (!(this instanceof WalletDB))
    return new WalletDB(options);

  if (WalletDB.global)
    return WalletDB.global;

  if (!options)
    options = {};

  EventEmitter.call(this);

  this.options = options;

  this.file = options.file;
  this.dir = options.dir;
  this.type = options.type;

  if (!this.file)
    this.file = bcoin.dir + '/wallet-' + network.type + '.db';

  if (!this.dir)
    this.dir = bcoin.dir + '/wallet-' + network.type;

  if (!this.type)
    this.type = 'leveldb';

  WalletDB.global = this;

  this._init();
}

inherits(WalletDB, EventEmitter);

WalletDB._db = {};

WalletDB.prototype._init = function _init() {
  if (this.type === 'file' && !bcoin.fs) {
    this.type = 'leveldb';
    utils.debug('`fs` module not available. Falling back to leveldb.');
  }

  if (this.type === 'file') {
    if (bcoin.fs) {
      try {
        bcoin.fs.statSync(this.dir, 0o750);
      } catch (e) {
        bcoin.fs.mkdirSync(this.dir);
      }
    }
    if (+process.env.BCOIN_FRESH === 1) {
      try {
        bcoin.fs.readdirSync(this.dir).forEach(function(file) {
          bcoin.fs.unlinkSync(this.dir + '/' + file);
        }, this);
      } catch (e) {
        ;
      }
    }
    return;
  }

  if (this.type === 'leveldb') {
    if (!WalletDB._db[this.file]) {
      WalletDB._db[this.file] = new levelup(this.file, {
        keyEncoding: 'ascii',
        valueEncoding: 'utf8',
        createIfMissing: true,
        errorIfExists: false,
        compression: true,
        cacheSize: 1 * 1024 * 1024,
        writeBufferSize: 1 * 1024 * 1024,
        // blockSize: 4 * 1024,
        maxOpenFiles: 1024,
        // blockRestartInterval: 16,
        db: bcoin.isBrowser
          ? require('level-js')
          : require('level' + 'down')
      });
    }
    this.db = WalletDB._db[this.file];
    return;
  }

  throw new Error('Unknown storage type: ' + this.type);
};

WalletDB.prototype.save = function save(id, json, callback) {
  callback = utils.asyncify(callback);

  if (this.type === 'leveldb')
    return this.saveDB(id, json, callback);

  if (this.type === 'file')
    return this.saveFile(id, json, callback);

  throw new Error('Unknown storage type: ' + this.type);
};

WalletDB.prototype.saveDB = function saveFile(id, json, callback) {
  var key;

  key = 'w/' + id;

  if (json instanceof bcoin.wallet) {
    json.store = true;
    json.db = this;
    json = json.toJSON(this.options.noPool);
  }

  callback = utils.asyncify(callback);

  json = JSON.stringify(json);

  this.db.put(key, json, callback);
};

WalletDB.prototype.saveFile = function saveFile(id, json, callback) {
  var file, options;

  file = this.dir + '/' + id + '.json';

  if (json instanceof bcoin.wallet) {
    json.store = true;
    json.db = this;
    json = json.toJSON(this.options.noPool);
  }

  callback = utils.asyncify(callback);

  if (!bcoin.fs)
    return callback();

  json = JSON.stringify(json, null, 2);

  options = {
    encoding: 'utf8',
    mode: 0o600
  };

  fs.writeFile(file, json, options, function(err) {
    if (err)
      return callback(err);

    return callback(null, file);
  });
};

WalletDB.prototype.getJSON = function getJSON(id, passphrase, callback) {
  if (typeof passphrase === 'function') {
    callback = passphrase;
    passphrase = null;
  }

  callback = utils.asyncify(callback);

  if (id instanceof bcoin.wallet) {
    id = wallet.id;
    json.store = true;
    json.db = this;
  }

  if (this.type === 'leveldb')
    return this.getDB(id, passphrase, callback);

  if (this.type === 'file')
    return this.getFile(id, passphrase, callback);

  throw new Error('Unknown storage type: ' + this.type);
};

WalletDB.prototype.getFile = function getFile(id, passphrase, callback) {
  var self = this;
  var file;

  callback = utils.asyncify(callback);

  if (!bcoin.fs)
    return callback();

  if (!id)
    return callback();

  file = this.dir + '/' + id + '.json';

  fs.readFile(file, 'utf8', function(err, json) {
    var options;

    if (err && err.code === 'ENOENT')
      return callback();

    if (err)
      return callback(err);

    try {
      options = bcoin.wallet._fromJSON(JSON.parse(json), passphrase);
    } catch (e) {
      return callback(e);
    }

    options.store = true;
    options.db = self;

    return callback(null, options);
  });
};

WalletDB.prototype.getDB = function getDB(id, passphrase, callback) {
  var self = this;
  var key;

  callback = utils.asyncify(callback);

  key = 'w/' + id;

  this.db.get(key, function(err, json) {
    var options;

    if (err && err.type === 'NotFoundError')
      return callback();

    if (err)
      return callback(err);

    try {
      options = bcoin.wallet._fromJSON(JSON.parse(json), passphrase);
    } catch (e) {
      return callback(e);
    }

    options.store = true;
    options.db = self;

    return callback(null, options);
  });
};

WalletDB.prototype.get = function get(id, passphrase, callback) {
  callback = utils.asyncify(callback);
  return this.getJSON(id, passphrase, function(err, options) {
    if (err)
      return callback(err);

    if (!options)
      return callback();

    return callback(null, new bcoin.wallet(options));
  });
};

WalletDB.prototype.create = function create(options, callback) {
  var self = this;
  callback = utils.asyncify(callback);
  return this.getJSON(options.id, options.passphrase, function(err, opt) {
    if (err)
      return callback(err);

    if (!opt) {
      options.store = true;
      options.db = self;
      return callback(null, new bcoin.wallet(options));
    }

    return callback(null, new bcoin.wallet(opt));
  });
};

/**
 * Expose
 */

module.exports = WalletDB;
