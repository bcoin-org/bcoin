/*!
 * client.js - http client for wallets
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const {NodeClient} = require('bclient');
const util = require('../utils/util');
const TX = require('../primitives/tx');
const hash256 = require('bcrypto/lib/hash256');

const parsers = {
  'block connect': (entry, txs) => parseBlock(entry, txs),
  'block disconnect': entry => [parseEntry(entry)],
  'block rescan': (entry, txs) => parseBlock(entry, txs),
  'chain reset': entry => [parseEntry(entry)],
  'tx': tx => [TX.fromRaw(tx)]
};

class WalletClient extends NodeClient {
  constructor(options) {
    super(options);
  }

  bind(event, handler) {
    const parser = parsers[event];

    if (!parser) {
      super.bind(event, handler);
      return;
    }

    super.bind(event, (...args) => {
      return handler(...parser(...args));
    });
  }

  hook(event, handler) {
    const parser = parsers[event];

    if (!parser) {
      super.hook(event, handler);
      return;
    }

    super.hook(event, (...args) => {
      return handler(...parser(...args));
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
