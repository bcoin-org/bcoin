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
const hash256 = require('bcrypto/lib/hash256');
const util = require('../utils/util');

class WalletClient extends NodeClient {
  constructor(options) {
    super(options);
  }

  async open() {
    await super.open();

    this.parse('block connect', (entry, txs) => {
      return parseBlock(entry, txs);
    });

    this.parse('block disconnect', (entry) => {
      return parseEntry(entry);
    });

    this.parse('block rescan', (entry, txs) => {
      return parseBlock(entry, txs);
    });

    this.parse('chain reset', (tip) => {
      return parseEntry(tip);
    });

    this.parse('tx', (tx) => {
      return TX.fromRaw(tx);
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

  const h = hash256.digest(data.slice(0, 80));

  return {
    hash: h.toString('hex'),
    height: data.readUInt32LE(80, true),
    time: data.readUInt32LE(68, true)
  };
}

function parseBlock(entry, txs) {
  const block = parseEntry(entry);
  const out = [];

  for (const tx of txs)
    out.push(TX.fromRaw(tx));

  return [block, out];
}

/*
 * Expose
 */

module.exports = WalletClient;
