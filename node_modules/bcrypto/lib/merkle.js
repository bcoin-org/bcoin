/*!
 * merkle.js - merkle trees for bcrypto
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on bitcoin/bitcoin:
 *   Copyright (c) 2009-2019, The Bitcoin Core Developers (MIT License).
 *   Copyright (c) 2009-2019, The Bitcoin Developers (MIT License).
 *   https://github.com/bitcoin/bitcoin
 */

'use strict';

const assert = require('./internal/assert');

// Notes about unbalanced merkle trees:
//
// Bitcoin hashes odd nodes with themselves,
// allowing an attacker to add a duplicate
// TXID, creating an even number of leaves
// and computing the same root (CVE-2012-2459).
// In contrast, RFC 6962 simply propagates
// odd nodes up.
//
// RFC 6962:
//
//              R
//             / \
//            /   \
//           /     \
//          /       \
//         /         \
//        k           j <-- same as below
//       / \          |
//      /   \         |
//     /     \        |
//    h       i       j
//   / \     / \     / \
//  a   b   c   d   e   f
//
// Bitcoin Behavior:
//
//              R
//             / \
//            /   \
//           /     \
//          /       \
//         /         \
//        k           l <-- HASH(j || j)
//       / \          |
//      /   \         |
//     /     \        |
//    h       i       j
//   / \     / \     / \
//  a   b   c   d   e   f
//
// This creates a situation where these leaves:
//
//        R
//       / \
//      /   \
//     /     \
//    d       e <-- HASH(c || c)
//   / \     / \
//  a   b   c   c
//
// Compute the same root as:
//
//       R
//      / \
//     /   \
//    d     e <-- HASH(c || c)
//   / \    |
//  a   b   c
//
// Why does this matter? Duplicate TXIDs are
// invalid right? They're spending the same
// inputs! The problem arises in certain
// implementation optimizations which may
// mark a block hash invalid. In other words,
// an invalid block shares the same block
// hash as a valid one!
//
// See:
//   https://tools.ietf.org/html/rfc6962#section-2.1
//   https://nvd.nist.gov/vuln/detail/CVE-2012-2459
//   https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-2459
//   https://bitcointalk.org/?topic=81749

/**
 * Build a merkle tree from leaves.
 * @param {Object} alg
 * @param {Buffer[]} leaves
 * @returns {Array} [nodes, malleated]
 */

function createTree(alg, leaves) {
  assert(alg && typeof alg.root === 'function');
  assert(Array.isArray(leaves));

  const nodes = new Array(leaves.length);

  for (let i = 0; i < leaves.length; i++)
    nodes[i] = leaves[i];

  let size = nodes.length;
  let malleated = false;
  let i = 0;

  if (size === 0) {
    nodes.push(alg.zero);
    return [nodes, malleated];
  }

  while (size > 1) {
    for (let j = 0; j < size; j += 2) {
      const k = Math.min(j + 1, size - 1);
      const left = nodes[i + j];
      const right = nodes[i + k];

      if (k === j + 1 && k + 1 === size
          && left.equals(right)) {
        malleated = true;
      }

      const hash = alg.root(left, right);

      nodes.push(hash);
    }

    i += size;

    size = (size + 1) >>> 1;
  }

  return [nodes, malleated];
}

/**
 * Calculate merkle root from leaves.
 * @param {Object} alg
 * @param {Buffer[]} leaves
 * @returns {Array} [root, malleated]
 */

function createRoot(alg, leaves) {
  assert(alg && typeof alg.root === 'function');
  assert(Array.isArray(leaves));

  const [nodes, malleated] = createTree(alg, leaves);
  const root = nodes[nodes.length - 1];

  return [root, malleated];
}

/**
 * Collect a merkle branch from vector index.
 * @param {Object} alg
 * @param {Number} index
 * @param {Buffer[]} leaves
 * @returns {Buffer[]} branch
 */

function createBranch(alg, index, leaves) {
  assert(alg && typeof alg.root === 'function');
  assert((index >>> 0) === index);
  assert(Array.isArray(leaves));
  assert(index < leaves.length);

  let size = leaves.length;

  const [nodes] = createTree(alg, leaves);
  const branch = [];

  let i = 0;

  while (size > 1) {
    const j = Math.min(index ^ 1, size - 1);

    branch.push(nodes[i + j]);

    index >>>= 1;

    i += size;

    size = (size + 1) >>> 1;
  }

  return branch;
}

/**
 * Derive merkle root from branch.
 * @param {Object} alg
 * @param {Buffer} hash
 * @param {Buffer[]} branch
 * @param {Number} index
 * @returns {Buffer} root
 */

function deriveRoot(alg, hash, branch, index) {
  assert(alg && typeof alg.root === 'function');
  assert(Buffer.isBuffer(hash));
  assert(Array.isArray(branch));
  assert((index >>> 0) === index);

  let root = hash;

  for (const hash of branch) {
    if ((index & 1) && hash.equals(root))
      return alg.zero;

    if (index & 1)
      root = alg.root(hash, root);
    else
      root = alg.root(root, hash);

    index >>>= 1;
  }

  return root;
}

/*
 * Expose
 */

exports.createTree = createTree;
exports.createRoot = createRoot;
exports.createBranch = createBranch;
exports.deriveRoot = deriveRoot;
