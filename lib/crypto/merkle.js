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

  if (size === 0) {
    nodes.push(Buffer.alloc(32));
    return [nodes, malleated];
  }

  for (let i = 0; size > 1; size = (size + 1) >>> 1) {
    for (let j = 0; j < size; j += 2) {
      let k = Math.min(j + 1, size - 1);
      let left = nodes[i + j];
      let right = nodes[i + k];
      let hash;

      if (k === j + 1 && k + 1 === size
          && left.equals(right)) {
        malleated = true;
      }

      hash = digest.root256(left, right);

      nodes.push(hash);
    }
    i += size;
  }

  return [nodes, malleated];
};

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
  let [nodes] = exports.createTree(leaves);
  let branch = [];

  for (let i = 0; size > 1; size = (size + 1) >>> 1) {
    let j = Math.min(index ^ 1, size - 1);
    branch.push(nodes[i + j]);
    index >>>= 1;
    i += size;
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
  for (let otherside of branch) {
    if (index & 1)
      hash = digest.root256(otherside, hash);
    else
      hash = digest.root256(hash, otherside);

    index >>>= 1;
  }

  return hash;
};
