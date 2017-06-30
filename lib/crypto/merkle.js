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

const digest = require('./digest');
const native = require('../native').binding;

/**
 * Build a merkle tree from leaves.
 * Note that this will mutate the `leaves` array!
 * @param {Buffer[]} leaves
 * @returns {Array} [nodes, malleated]
 */

exports.createTree = function createTree(leaves) {
  let nodes = leaves;
  let size = leaves.length;
  let malleated = false;
  let data;

  if (size === 0) {
    let hash = Buffer.allocUnsafe(32);
    hash.fill(0);
    nodes.push(hash);
    return [nodes, malleated];
  }

  data = Buffer.allocUnsafe(64);

  for (let j = 0; size > 1; size = (size + 1) >>> 1) {
    for (let i = 0; i < size; i += 2) {
      let k = Math.min(i + 1, size - 1);
      let left = nodes[j + i];
      let right = nodes[j + k];
      let hash;

      if (k === i + 1 && k + 1 === size
          && left.equals(right)) {
        malleated = true;
      }

      left.copy(data, 0);
      right.copy(data, 32);

      hash = digest.hash256(data);

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
  let [nodes, malleated] = exports.createTree(leaves);
  let root = nodes[nodes.length - 1];
  return [root, malleated];
};

/**
 * Collect a merkle branch at vector index.
 * @param {Number} index
 * @param {Buffer[]} leaves
 * @returns {Buffer[]} branch
 */

exports.createBranch = function createBranch(index, leaves) {
  let size = leaves.length;
  let tree = exports.createTree(leaves);
  let branch = [];
  let j = 0;

  for (; size > 1; size = (size + 1) >>> 1) {
    let i = Math.min(index ^ 1, size - 1);
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
  let data;

  if (branch.length === 0)
    return hash;

  data = Buffer.allocUnsafe(64);

  for (let i = 0; i < branch.length; i++) {
    let otherside = branch[i];

    if (index & 1) {
      otherside.copy(data, 0);
      hash.copy(data, 32);
    } else {
      hash.copy(data, 0);
      otherside.copy(data, 32);
    }

    hash = digest.hash256(data);
    index >>>= 1;
  }

  return hash;
};

if (native)
  exports.verifyBranch = native.verifyMerkleBranch;
