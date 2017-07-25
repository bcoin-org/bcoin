/*!
 * memwallet.js - in-memory wallet object for bcoin
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const Network = require('../../lib/protocol/network');
const util = require('../../lib/utils/util');
const MTX = require('../../lib/primitives/mtx');
const HD = require('../../lib/hd/hd');
const Bloom = require('../../lib/utils/bloom');
const KeyRing = require('../../lib/primitives/keyring');
const Outpoint = require('../../lib/primitives/outpoint');
const Coin = require('../../lib/primitives/coin');

function MemWallet(options) {
  if (!(this instanceof MemWallet))
    return new MemWallet(options);

  this.network = Network.primary;
  this.master = null;
  this.key = null;
  this.witness = false;
  this.account = 0;
  this.receiveDepth = 1;
  this.changeDepth = 1;
  this.receive = null;
  this.change = null;
  this.map = new Set();
  this.coins = new Map();
  this.spent = new Map();
  this.paths = new Map();
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

  if (options.witness != null) {
    assert(typeof options.witness === 'boolean');
    this.witness = options.witness;
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
  let i;

  if (!this.master)
    this.master = HD.PrivateKey.generate();

  if (!this.key)
    this.key = this.master.deriveBIP44(this.account);

  i = this.receiveDepth;
  while (i--)
    this.createReceive();

  i = this.changeDepth;
  while (i--)
    this.createChange();
};

MemWallet.prototype.createReceive = function createReceive() {
  let index = this.receiveDepth++;
  let key = this.deriveReceive(index);
  let hash = key.getHash('hex');
  this.filter.add(hash, 'hex');
  this.paths.set(hash, new Path(hash, 0, index));
  this.receive = key;
  return key;
};

MemWallet.prototype.createChange = function createChange() {
  let index = this.changeDepth++;
  let key = this.deriveChange(index);
  let hash = key.getHash('hex');
  this.filter.add(hash, 'hex');
  this.paths.set(hash, new Path(hash, 1, index));
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
  let key = this.master.deriveBIP44(this.account);
  key = key.derive(branch).derive(index);
  key = new KeyRing({
    network: this.network,
    privateKey: key.privateKey,
    witness: this.witness
  });
  key.witness = this.witness;
  return key;
};

MemWallet.prototype.getKey = function getKey(hash) {
  let path = this.paths.get(hash);
  if (!path)
    return;
  return this.derivePath(path);
};

MemWallet.prototype.getPath = function getPath(hash) {
  return this.paths.get(hash);
};

MemWallet.prototype.getCoin = function getCoin(key) {
  return this.coins.get(key);
};

MemWallet.prototype.getUndo = function getUndo(key) {
  return this.spent.get(key);
};

MemWallet.prototype.addCoin = function addCoin(coin) {
  let op = Outpoint(coin.hash, coin.index);
  let key = op.toKey();

  this.filter.add(op.toRaw());

  this.spent.delete(key);

  this.coins.set(key, coin);
  this.balance += coin.value;
};

MemWallet.prototype.removeCoin = function removeCoin(key) {
  let coin = this.coins.get(key);

  if (!coin)
    return;

  this.spent.set(key, coin);
  this.balance -= coin.value;

  this.coins.delete(key);
};

MemWallet.prototype.getAddress = function getAddress() {
  return this.receive.getAddress();
};

MemWallet.prototype.getReceive = function getReceive() {
  return this.receive.getAddress();
};

MemWallet.prototype.getChange = function getChange() {
  return this.change.getAddress();
};

MemWallet.prototype.getCoins = function getCoins() {
  let coins = [];

  for (let coin of this.coins.values())
    coins.push(coin);

  return coins;
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
  let i, tx;

  for (i = 0; i < txs.length; i++) {
    tx = txs[i];
    this.addTX(tx, entry.height);
  }
};

MemWallet.prototype.removeBlock = function removeBlock(entry, txs) {
  let i, tx;

  for (i = txs.length - 1; i >= 0; i--) {
    tx = txs[i];
    this.removeTX(tx, entry.height);
  }
};

MemWallet.prototype.addTX = function addTX(tx, height) {
  let hash = tx.hash('hex');
  let result = false;
  let i, op, path, addr, coin, input, output;

  if (height == null)
    height = -1;

  if (this.map.has(hash))
    return true;

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

  if (result) {
    this.txs++;
    this.map.add(hash);
  }

  return result;
};

MemWallet.prototype.removeTX = function removeTX(tx, height) {
  let hash = tx.hash('hex');
  let result = false;
  let i, op, coin, input;

  if (!this.map.has(hash))
    return false;

  for (i = 0; i < tx.outputs.length; i++) {
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

  this.map.delete(hash);

  return result;
};

MemWallet.prototype.deriveInputs = function deriveInputs(mtx) {
  let keys = [];
  let i, input, coin, addr, path, key;

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
  let coins = this.getCoins();

  if (!options)
    options = {};

  return mtx.fund(coins, {
    selection: options.selection || 'age',
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

MemWallet.prototype.template = function template(mtx) {
  let keys = this.deriveInputs(mtx);
  mtx.template(keys);
};

MemWallet.prototype.sign = function sign(mtx) {
  let keys = this.deriveInputs(mtx);
  mtx.template(keys);
  mtx.sign(keys);
};

MemWallet.prototype.create = async function create(options) {
  let mtx = new MTX(options);

  await this.fund(mtx, options);

  assert(mtx.getFee() <= MTX.Selector.MAX_FEE, 'TX exceeds MAX_FEE.');

  mtx.sortMembers();

  if (options.locktime != null)
    mtx.setLocktime(options.locktime);

  this.sign(mtx);

  if (!mtx.isSigned())
    throw new Error('Cannot sign tx.');

  return mtx;
};

MemWallet.prototype.send = async function send(options) {
  let mtx = await this.create(options);
  this.addTX(mtx.toTX());
  return mtx;
};

function Path(hash, branch, index) {
  this.hash = hash;
  this.branch = branch;
  this.index = index;
}

module.exports = MemWallet;
