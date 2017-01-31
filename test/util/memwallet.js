/*!
 * memwallet.js - in-memory wallet object for bcoin
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var assert = require('assert');
var Network = require('../../lib/protocol/network');
var util = require('../../lib/utils/util');
var MTX = require('../../lib/primitives/mtx');
var HD = require('../../lib/hd/hd');
var Bloom = require('../../lib/utils/bloom');
var KeyRing = require('../../lib/primitives/keyring');
var Outpoint = require('../../lib/primitives/outpoint');
var Coin = require('../../lib/primitives/coin');

function MemWallet(options) {
  if (!(this instanceof MemWallet))
    return new MemWallet(options);

  this.network = Network.primary;
  this.master = null;
  this.key = null;
  this.account = 0;
  this.receiveDepth = 1;
  this.changeDepth = 1;
  this.receive = null;
  this.change = null;
  this.coins = {};
  this.undo = {};
  this.paths = {};
  this.balance = 0;
  this.txs = 0;
  this.filter = Bloom.fromRate(1000000, 0.001, -1);

  if (options)
    this.fromOptions(options);

  this.init();
}

MemWallet.prototype.fromOptions = function fromOptions(options) {
  if (options.network != null) {
    assert(options.network);
    this.network = Network.get(options.network);
  }

  if (options.master != null) {
    assert(options.master);
    this.master = HD.PrivateKey.fromOptions(options.master, this.network);
  }

  if (options.key != null) {
    assert(HD.isPrivate(options.key));
    this.key = options.key;
  }

  if (options.account != null) {
    assert(typeof options.account === 'number');
    this.account = options.account;
  }

  if (options.receiveDepth != null) {
    assert(typeof options.receiveDepth === 'number');
    this.receiveDepth = options.receiveDepth;
  }

  if (options.changeDepth != null) {
    assert(typeof options.changeDepth === 'number');
    this.changeDepth = options.changeDepth;
  }

  return this;
};

MemWallet.prototype.init = function init() {
  var i;

  if (!this.master)
    this.master = HD.PrivateKey.fromMnemonic(null, this.network);

  if (!this.key)
    this.key = this.master.deriveAccount44(this.account);

  i = this.receiveDepth;
  while (i--)
    this.createReceive();

  i = this.changeDepth;
  while (i--)
    this.createChange();
};

MemWallet.prototype.createReceive = function createReceive() {
  var index = this.receiveDepth++;
  var key = this.deriveReceive(index);
  var hash = key.getHash('hex');
  this.filter.add(hash, 'hex');
  this.paths[hash] = new Path(hash, 0, index);
  this.receive = key;
  return key;
};

MemWallet.prototype.createChange = function createChange() {
  var index = this.changeDepth++;
  var key = this.deriveChange(index);
  var hash = key.getHash('hex');
  this.filter.add(hash, 'hex');
  this.paths[hash] = new Path(hash, 1, index);
  this.change = key;
  return key;
};

MemWallet.prototype.deriveReceive = function deriveReceive(index) {
  return this.deriveKey(0, index);
};

MemWallet.prototype.deriveChange = function deriveChange(index) {
  return this.deriveKey(1, index);
};

MemWallet.prototype.derivePath = function derivePath(path) {
  return this.deriveKey(path.branch, path.index);
};

MemWallet.prototype.deriveKey = function deriveKey(branch, index) {
  var key = this.master.deriveAccount44(this.account);
  key = key.derive(branch).derive(index);
  return new KeyRing({
    network: this.network,
    privateKey: key.privateKey
  });
};

MemWallet.prototype.getKey = function getKey(hash) {
  var path = this.paths[hash];
  if (!path)
    return;
  return this.derivePath(path);
};

MemWallet.prototype.getPath = function getPath(hash) {
  return this.paths[hash];
};

MemWallet.prototype.getCoin = function getCoin(key) {
  return this.coins[key];
};

MemWallet.prototype.getUndo = function getUndo(key) {
  return this.undo[key];
};

MemWallet.prototype.addCoin = function addCoin(coin) {
  var op = Outpoint(coin.hash, coin.index);
  var key = op.toKey();

  this.filter.add(op.toRaw());

  delete this.undo[key];

  this.coins[key] = coin;
  this.balance += coin.value;
};

MemWallet.prototype.removeCoin = function removeCoin(key) {
  var coin = this.coins[key];

  if (!coin)
    return;

  this.undo[key] = coin;
  this.balance -= coin.value;

  delete this.coins[key];
};

MemWallet.prototype.getReceive = function getReceive() {
  return this.receive.getAddress();
};

MemWallet.prototype.getChange = function getChange() {
  return this.change.getAddress();
};

MemWallet.prototype.getCoins = function getCoins() {
  return util.values(this.coins);
};

MemWallet.prototype.syncKey = function syncKey(path) {
  switch (path.branch) {
    case 0:
      if (path.index === this.receiveDepth - 1)
        this.createReceive();
      break;
    case 1:
      if (path.index === this.changeDepth - 1)
        this.createChange();
      break;
    default:
      assert(false);
      break;
  }
};

MemWallet.prototype.addBlock = function addBlock(entry, txs) {
  var i, tx;

  for (i = 0; i < txs.length; i++) {
    tx = txs[i];
    this.addTX(tx, entry.height);
  }
};

MemWallet.prototype.removeBlock = function removeBlock(entry, txs) {
  var i, tx;

  for (i = txs.length - 1; i >= 0; i--) {
    tx = txs[i];
    this.removeTX(tx, entry.height);
  }
};

MemWallet.prototype.addTX = function addTX(tx, height) {
  var result = false;
  var i, op, path, addr, coin, input, output;

  if (height == null)
    height = -1;

  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];
    op = input.prevout.toKey();
    coin = this.getCoin(op);

    if (!coin)
      continue;

    result = true;

    this.removeCoin(op);
  }

  for (i = 0; i < tx.outputs.length; i++) {
    output = tx.outputs[i];
    addr = output.getHash('hex');

    if (!addr)
      continue;

    path = this.getPath(addr);

    if (!path)
      continue;

    result = true;
    coin = Coin.fromTX(tx, i, height);

    this.addCoin(coin);
    this.syncKey(path);
  }

  if (result)
    this.txs++;

  return result;
};

MemWallet.prototype.removeTX = function removeTX(tx, height) {
  var hash = tx.hash('hex');
  var result = false;
  var i, op, coin, input, output;

  for (i = 0; i < tx.outputs.length; i++) {
    output = tx.outputs[i];
    op = Outpoint(hash, i).toKey();
    coin = this.getCoin(op);

    if (!coin)
      continue;

    result = true;

    this.removeCoin(op);
  }

  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];
    op = input.prevout.toKey();
    coin = this.getUndo(op);

    if (!coin)
      continue;

    result = true;

    this.addCoin(coin);
  }

  if (result)
    this.txs--;

  return result;
};

MemWallet.prototype.deriveInputs = function deriveInputs(mtx) {
  var keys = [];
  var i, input, coin, addr, path, key;

  for (i = 0; i < mtx.inputs.length; i++) {
    input = mtx.inputs[i];
    coin = mtx.view.getOutput(input);

    if (!coin)
      continue;

    addr = coin.getHash('hex');

    if (!addr)
      continue;

    path = this.getPath(addr);

    if (!path)
      continue;

    key = this.derivePath(path);

    keys.push(key);
  }

  return keys;
};

MemWallet.prototype.fund = function fund(mtx, options) {
  var coins = this.getCoins();

  if (!options)
    options = {};

  return mtx.fund(coins, {
    selection: options.selection,
    round: options.round,
    depth: options.depth,
    hardFee: options.hardFee,
    subtractFee: options.subtractFee,
    changeAddress: this.getChange(),
    height: -1,
    rate: options.rate,
    maxFee: options.maxFee
  });
};

MemWallet.prototype.sign = function sign(mtx) {
  var keys = this.deriveInputs(mtx);
  mtx.template(keys);
  mtx.sign(keys);
};

MemWallet.prototype.send = function send(options) {
  var self = this;
  var mtx = new MTX(options);
  var tx;

  this.fund(mtx, options).then(function() {
    assert(mtx.getFee() <= MTX.Selector.MAX_FEE, 'TX exceeds MAX_FEE.');

    mtx.sortMembers();

    if (options.locktime != null)
      mtx.setLocktime(options.locktime);

    self.sign(mtx);

    if (!mtx.isSigned())
      throw new Error('Cannot sign tx.');

    tx = mtx.toTX();

    self.addTX(tx);
  }).catch(function(err) {
    throw err;
  });

  return tx;
};

function Path(hash, branch, index) {
  this.hash = hash;
  this.branch = branch;
  this.index = index;
}

module.exports = MemWallet;
