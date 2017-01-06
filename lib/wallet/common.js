/*!
 * common.js - commonly required functions for wallet.
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var common = exports;

/**
 * Test whether a string is eligible
 * to be used as a name or ID.
 * @param {String} key
 * @returns {Boolean}
 */

common.isName = function isName(key) {
  if (typeof key !== 'string')
    return false;

  if (!/^[\-\._0-9A-Za-z]+$/.test(key))
    return false;

  return key.length >= 1 && key.length <= 40;
};

/**
 * Sort an array of transactions in dependency order.
 * @param {TX[]} txs
 * @returns {TX[]}
 */

common.sortTX = function sortTX(txs) {
  var depMap = {};
  var count = {};
  var result = [];
  var top = [];
  var map = txs;
  var i, j, tx, hash, input;
  var prev, hasDeps, deps;

  if (Array.isArray(txs)) {
    map = {};
    for (i = 0; i < txs.length; i++) {
      tx = txs[i];
      hash = tx.hash('hex');
      map[hash] = tx;
    }
  }

  for (i = 0; i < txs.length; i++) {
    tx = txs[i];
    hash = tx.hash('hex');
    hasDeps = false;

    count[hash] = 0;

    for (j = 0; j < tx.inputs.length; j++) {
      input = tx.inputs[j];
      prev = input.prevout.hash;

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

  for (i = 0; i < top.length; i++) {
    tx = top[i];
    hash = tx.hash('hex');

    result.push(tx);

    deps = depMap[hash];

    if (!deps)
      continue;

    for (j = 0; j < deps.length; j++) {
      tx = deps[j];
      hash = tx.hash('hex');

      if (--count[hash] === 0)
        top.push(tx);
    }
  }

  return result;
};
