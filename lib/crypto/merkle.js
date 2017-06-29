/*!
 * merkle.js - merkle trees for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

/**
 * @module crypto/merkle
 */

var digest = require('./digest');
var native = require('../native').binding;

/**
 * Build a merkle tree from leaves.
 * Note that this will mutate the `leaves` array!
 * @param {Buffer[]} leaves
 * @returns {Array} [nodes, malleated]
 */

exports.createTree = function createTree(leaves) {
  var nodes = leaves;
  var size = leaves.length;
  var malleated = false;
  var i, j, k, hash, left, right, lr;

  if (size === 0) {
    hash = Buffer.allocUnsafe(32);
    hash.fill(0);
    nodes.push(hash);
    return [nodes, malleated];
  }

  lr = Buffer.allocUnsafe(64);

  for (j = 0; size > 1; size = (size + 1) >>> 1) {
    for (i = 0; i < size; i += 2) {
      k = Math.min(i + 1, size - 1);
      left = nodes[j + i];
      right = nodes[j + k];

      if (k === i + 1 && k + 1 === size
          && left.equals(right)) {
        malleated = true;
      }

      left.copy(lr, 0);
      right.copy(lr, 32);

      hash = digest.hash256(lr);

      nodes.push(hash);
    }
    j += size;
  }

  return [nodes, malleated];
};

if (native)
  exports.createTree = native.createMerkleTree;

/**
 * Calculate merkle root from leaves.
 * @param {Buffer[]} leaves
 * @returns {Array} [root, malleated]
 */

exports.createRoot = function createRoot(leaves) {
  var [nodes, malleated] = exports.createTree(leaves);
  var root = nodes[nodes.length - 1];
  return [root, malleated];
};

/**
 * Collect a merkle branch at vector index.
 * @param {Number} index
 * @param {Buffer[]} leaves
 * @returns {Buffer[]} branch
 */

exports.createBranch = function createBranch(index, leaves) {
  var size = leaves.length;
  var tree = exports.createTree(leaves);
  var branch = [];
  var j = 0;
  var i;

  for (; size > 1; size = (size + 1) >>> 1) {
    i = Math.min(index ^ 1, size - 1);
    branch.push(tree.nodes[j + i]);
    index >>>= 1;
    j += size;
  }

  return branch;
};

/**
 * Check a merkle branch at vector index.
 * @param {Buffer} hash
 * @param {Buffer[]} branch
 * @param {Number} index
 * @returns {Buffer} Hash.
 */

exports.verifyBranch = function verifyBranch(hash, branch, index) {
  var i, otherside, lr;

  if (branch.length === 0)
    return hash;

  lr = Buffer.allocUnsafe(64);

  for (i = 0; i < branch.length; i++) {
    otherside = branch[i];

    if (index & 1) {
      otherside.copy(lr, 0);
      hash.copy(lr, 32);
    } else {
      hash.copy(lr, 0);
      otherside.copy(lr, 32);
    }

    hash = digest.hash256(lr);
    index >>>= 1;
  }

  return hash;
};

if (native)
  exports.verifyBranch = native.verifyMerkleBranch;
