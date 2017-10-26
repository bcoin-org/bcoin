/*!
 * client.js - http client for wallets
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const {NodeClient} = require('bclient');
const TX = require('../primitives/tx');
const digest = require('bcrypto/lib/digest');
const util = require('../utils/util');

class WalletClient extends NodeClient {
  constructor(options) {
    super(options);
  }

  async open() {
    await super.open();

    this.listen('block connect', (entry, txs) => {
      this.emit('block connect', ...parseBlock(entry, txs));
    });

    this.listen('block disconnect', (entry) => {
      this.emit('block disconnect', parseEntry(entry));
    });

    this.listen('block rescan', (entry, txs) => {
      this.emit('block rescan', ...parseBlock(entry, txs));
    });

    this.listen('chain reset', (tip) => {
      this.emit('chain reset', parseEntry(tip));
    });

    this.listen('tx', (tx) => {
      this.emit('tx', TX.fromRaw(tx));
    });
  }

  async getTip() {
    return parseEntry(await super.getTip());
  }

  async getEntry(block) {
    if (typeof block === 'string')
      block = util.revHex(block);

    return parseEntry(await super.getEntry(block));
  }

  async send(tx) {
    return super.send(tx.toRaw());
  }

  async setFilter(filter) {
    return super.setFilter(filter.toRaw());
  }

  async rescan(start) {
    if (typeof start === 'string')
      start = util.revHex(start);

    return super.rescan(start);
  }
}

/*
 * Helpers
 */

function parseEntry(data) {
  assert(Buffer.isBuffer(data));
  assert(data.length >= 84);

  const h = digest.hash256(data.slice(0, 80));

  return {
    hash: h.toString('hex'),
    height: data.readUInt32LE(80, true),
    time: data.readUInt32LE(68, true)
  };
}

function parseBlock(entry, txs) {
  const block = parseEntry(entry);
  const out = [];

  for (const raw of txs) {
    const tx = TX.fromRaw(raw);
    out.push(tx);
  }

  return [block, out];
}

/*
 * Expose
 */

module.exports = WalletClient;
