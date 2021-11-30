/*!
 * records.js - records for bcoin chaindb
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('bsert');
const bio = require('bufio');
const consensus = require('../../protocol/consensus');
const Network = require('../../protocol/network');

/**
 * ChainFlags
 */

class ChainFlags {
  /**
   * Create chain flags.
   * @alias module:blockchain.ChainFlags
   * @constructor
   */

  constructor(options) {
    this.network = Network.primary;
    this.spv = false;
    this.witness = true;
    this.bip91 = false;
    this.bip148 = false;
    this.prune = false;

    if (options)
      this.fromOptions(options);
  }

  fromOptions(options) {
    this.network = Network.get(options.network);

    if (options.spv != null) {
      assert(typeof options.spv === 'boolean');
      this.spv = options.spv;
    }

    if (options.bip91 != null) {
      assert(typeof options.bip91 === 'boolean');
      this.bip91 = options.bip91;
    }

    if (options.bip148 != null) {
      assert(typeof options.bip148 === 'boolean');
      this.bip148 = options.bip148;
    }

    if (options.prune != null) {
      assert(typeof options.prune === 'boolean');
      this.prune = options.prune;
    }

    return this;
  }

  static fromOptions(data) {
    return new ChainFlags().fromOptions(data);
  }

  toRaw() {
    const bw = bio.write(12);

    let flags = 0;

    if (this.spv)
      flags |= 1 << 0;

    if (this.witness)
      flags |= 1 << 1;

    if (this.prune)
      flags |= 1 << 2;

    if (this.bip91)
      flags |= 1 << 5;

    if (this.bip148)
      flags |= 1 << 6;

    bw.writeU32(this.network.magic);
    bw.writeU32(flags);
    bw.writeU32(0);

    return bw.render();
  }

  fromRaw(data) {
    const br = bio.read(data);

    this.network = Network.fromMagic(br.readU32());

    const flags = br.readU32();

    this.spv = (flags & 1) !== 0;
    this.witness = (flags & 2) !== 0;
    this.prune = (flags & 4) !== 0;
    this.bip91 = (flags & 32) !== 0;
    this.bip148 = (flags & 64) !== 0;

    return this;
  }

  static fromRaw(data) {
    return new ChainFlags().fromRaw(data);
  }
}

/**
 * Chain State
 */

class ChainState {
  /**
   * Create chain state.
   * @alias module:blockchain.ChainState
   * @constructor
   */

  constructor() {
    this.tip = consensus.ZERO_HASH;
    this.tx = 0;
    this.coin = 0;
    this.value = 0;
    this.committed = false;
  }

  clone() {
    const state = new ChainState();
    state.tip = this.tip;
    state.tx = this.tx;
    state.coin = this.coin;
    state.value = this.value;
    return state;
  }

  connect(block) {
    this.tx += block.txs.length;
  }

  disconnect(block) {
    this.tx -= block.txs.length;
  }

  add(coin) {
    this.coin += 1;
    this.value += coin.value;
  }

  spend(coin) {
    this.coin -= 1;
    this.value -= coin.value;
  }

  commit(hash) {
    this.tip = hash;
    this.committed = true;
    return this.toRaw();
  }

  toRaw() {
    const bw = bio.write(56);
    bw.writeHash(this.tip);
    bw.writeU64(this.tx);
    bw.writeU64(this.coin);
    bw.writeU64(this.value);
    return bw.render();
  }

  static fromRaw(data) {
    const state = new ChainState();
    const br = bio.read(data);
    state.tip = br.readHash();
    state.tx = br.readU64();
    state.coin = br.readU64();
    state.value = br.readU64();
    return state;
  }
}

/*
 * Expose
 */

module.exports = {
  ChainFlags,
  ChainState
};
