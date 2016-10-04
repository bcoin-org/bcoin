/*!
 * pathinfo.js - pathinfo object for bcoin
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var utils = require('../utils/utils');

/**
 * Path Info
 * @constructor
 * @param {WalletDB} db
 * @param {WalletID} wid
 * @param {TX} tx
 * @param {Object} table
 */

function PathInfo(wallet, tx, paths) {
  if (!(this instanceof PathInfo))
    return new PathInfo(wallet, tx, paths);

  // All relevant Accounts for
  // inputs and outputs (for database indexing).
  this.accounts = [];

  // All output paths (for deriving during sync).
  this.paths = [];

  // Wallet
  this.wallet = wallet;

  // Wallet ID
  this.wid = wallet.wid;

  // Wallet Label
  this.id = wallet.id;

  // Map of address hashes->paths.
  this.pathMap = {};

  // Current transaction.
  this.tx = null;

  // Wallet-specific details cache.
  this._details = null;
  this._json = null;

  if (tx)
    this.fromTX(tx, paths);
}

/**
 * Instantiate path info from a transaction.
 * @private
 * @param {TX} tx
 * @param {Object} table
 * @returns {PathInfo}
 */

PathInfo.prototype.fromTX = function fromTX(tx, paths) {
  var uniq = {};
  var i, hashes, hash, path;

  this.tx = tx;

  for (i = 0; i < paths.length; i++) {
    path = paths[i];

    this.pathMap[path.hash] = path;

    if (!uniq[path.account]) {
      uniq[path.account] = true;
      this.accounts.push(path.account);
    }
  }

  hashes = tx.getOutputHashes('hex');

  for (i = 0; i < hashes.length; i++) {
    hash = hashes[i];
    path = this.pathMap[hash];
    if (path)
      this.paths.push(path);
  }

  return this;
};

/**
 * Instantiate path info from a transaction.
 * @param {WalletDB} db
 * @param {WalletID} wid
 * @param {TX} tx
 * @param {Object} table
 * @returns {PathInfo}
 */

PathInfo.fromTX = function fromTX(wallet, tx, paths) {
  return new PathInfo(wallet).fromTX(tx, paths);
};

/**
 * Test whether the map has paths
 * for a given address hash.
 * @param {Hash} hash
 * @returns {Boolean}
 */

PathInfo.prototype.hasPath = function hasPath(hash) {
  if (!hash)
    return false;

  return this.pathMap[hash] != null;
};

/**
 * Get path for a given address hash.
 * @param {Hash} hash
 * @returns {Path}
 */

PathInfo.prototype.getPath = function getPath(hash) {
  if (!hash)
    return;

  return this.pathMap[hash];
};

/**
 * Convert path info to transaction details.
 * @returns {Details}
 */

PathInfo.prototype.toDetails = function toDetails() {
  var details = this._details;

  if (!details) {
    details = new Details(this);
    this._details = details;
  }

  return details;
};

/**
 * Convert path info to JSON details (caches json).
 * @returns {Object}
 */

PathInfo.prototype.toJSON = function toJSON() {
  var json = this._json;

  if (!json) {
    json = this.toDetails().toJSON();
    this._json = json;
  }

  return json;
};

/**
 * Transaction Details
 * @constructor
 * @param {PathInfo} info
 */

function Details(info) {
  if (!(this instanceof Details))
    return new Details(info);

  this.db = info.wallet.db;
  this.network = this.db.network;
  this.wid = info.wid;
  this.id = info.id;
  this.hash = info.tx.hash('hex');
  this.height = info.tx.height;
  this.block = info.tx.block;
  this.index = info.tx.index;
  this.confirmations = info.tx.getConfirmations(this.db.height);
  this.fee = info.tx.getFee();
  this.ts = info.tx.ts;
  this.ps = info.tx.ps;
  this.tx = info.tx;
  this.inputs = [];
  this.outputs = [];

  this.init(info.pathMap);
}

/**
 * Initialize transactions details
 * by pushing on mapped members.
 * @private
 * @param {Object} table
 */

Details.prototype.init = function init(map) {
  this._insert(this.tx.inputs, true, this.inputs, map);
  this._insert(this.tx.outputs, false, this.outputs, map);
};

/**
 * Insert members in the input or output vector.
 * @private
 * @param {Input[]|Output[]} vector
 * @param {Array} target
 * @param {Object} table
 */

Details.prototype._insert = function _insert(vector, input, target, map) {
  var i, io, address, hash, path, member;

  for (i = 0; i < vector.length; i++) {
    io = vector[i];
    member = new DetailsMember();

    if (input) {
      if (io.coin)
        member.value = io.coin.value;
    } else {
      member.value = io.value;
    }

    address = io.getAddress();

    if (address) {
      member.address = address;

      hash = address.getHash('hex');
      path = map[hash];

      if (path)
        member.path = path;
    }

    target.push(member);
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

/*
 * Expose
 */

module.exports = PathInfo;
