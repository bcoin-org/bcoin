/*!
 * common.js - commonly required functions for wallet.
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

/**
 * @exports wallet/common
 */

const common = exports;

/**
 * Test whether a string is eligible
 * to be used as a name or ID.
 * @param {String} key
 * @returns {Boolean}
 */

common.isName = function isName(key) {
  if (typeof key !== 'string')
    return false;

  if (key.length === 0)
    return false;

  if (!/^[\-\._0-9A-Za-z]+$/.test(key))
    return false;

  // Prevents __proto__
  // from being used.
  switch (key[0]) {
    case '_':
    case '-':
    case '.':
      return false;
  }

  switch (key[key.length - 1]) {
    case '_':
    case '-':
    case '.':
      return false;
  }

  return key.length >= 1 && key.length <= 40;
};

/**
 * Sort an array of transactions by time.
 * @param {TX[]} txs
 * @returns {TX[]}
 */

common.sortTX = function sortTX(txs) {
  return txs.sort((a, b) => {
    return a.ps - b.ps;
  });
};

/**
 * Sort an array of coins by height.
 * @param {Coin[]} txs
 * @returns {Coin[]}
 */

common.sortCoins = function sortCoins(coins) {
  return coins.sort((a, b) => {
    a = a.height === -1 ? 0x7fffffff : a.height;
    b = b.height === -1 ? 0x7fffffff : b.height;
    return a - b;
  });
};

/**
 * Sort an array of transactions in dependency order.
 * @param {TX[]} txs
 * @returns {TX[]}
 */

common.sortDeps = function sortDeps(txs) {
  let depMap = {};
  let count = {};
  let result = [];
  let top = [];
  let map = {};

  for (let tx of txs) {
    let hash = tx.hash('hex');
    map[hash] = tx;
  }

  for (let tx of txs) {
    let hash = tx.hash('hex');
    let hasDeps = false;

    count[hash] = 0;

    for (let input of tx.inputs) {
      let prev = input.prevout.hash;

      if (!map[prev])
        continue;

      count[hash] += 1;
      hasDeps = true;

      if (!depMap[prev])
        depMap[prev] = [];

      depMap[prev].push(tx);
    }

    if (hasDeps)
      continue;

    top.push(tx);
  }

  for (let tx of top) {
    let hash = tx.hash('hex');
    let deps = depMap[hash];

    result.push(tx);

    if (!deps)
      continue;

    for (let tx of deps) {
      let hash = tx.hash('hex');

      if (--count[hash] === 0)
        top.push(tx);
    }
  }

  return result;
};
