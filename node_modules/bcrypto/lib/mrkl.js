/*!
 * mrkl.js - merkle trees for bcrypto
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('./internal/assert');

/*
 * Constants
 */

const EMPTY = Buffer.alloc(0);
const INTERNAL = Buffer.from([0x01]);
const LEAF = Buffer.from([0x00]);

/**
 * Build a merkle tree from leaves.
 * @param {Object} alg
 * @param {Buffer[]} leaves
 * @returns {Buffer[]} nodes
 */

function createTree(alg, leaves) {
  assert(alg && typeof alg.multi === 'function');
  assert(Array.isArray(leaves));

  const nodes = [];
  const sentinel = hashEmpty(alg);

  for (const data of leaves) {
    const leaf = hashLeaf(alg, data);
    nodes.push(leaf);
  }

  let size = nodes.length;
  let i = 0;

  if (size === 0) {
    nodes.push(sentinel);
    return nodes;
  }

  while (size > 1) {
    for (let j = 0; j < size; j += 2) {
      const l = j;
      const r = j + 1;
      const left = nodes[i + l];

      let right;

      if (r < size)
        right = nodes[i + r];
      else
        right = sentinel;

      const hash = hashInternal(alg, left, right);
      nodes.push(hash);
    }

    i += size;

    size = (size + 1) >>> 1;
  }

  return nodes;
}

/**
 * Calculate merkle root from leaves.
 * @param {Object} alg
 * @param {Buffer[]} leaves
 * @returns {Buffer} root
 */

function createRoot(alg, leaves) {
  const nodes = createTree(alg, leaves);
  const root = nodes[nodes.length - 1];
  return root;
}

/**
 * Collect a merkle branch from vector index.
 * @param {Object} alg
 * @param {Number} index
 * @param {Buffer[]} leaves
 * @returns {Buffer[]} branch
 */

function createBranch(alg, index, leaves) {
  assert((index >>> 0) === index);

  const nodes = createTree(alg, leaves);
  const sentinel = hashEmpty(alg);
  const branch = [];

  let size = leaves.length;
  let i = 0;

  assert(index < leaves.length);

  while (size > 1) {
    const j = index ^ 1;

    if (j < size)
      branch.push(nodes[i + j]);
    else
      branch.push(sentinel);

    index >>>= 1;

    i += size;

    size = (size + 1) >>> 1;
  }

  return branch;
}

/**
 * Derive merkle root from branch.
 * @param {Object} alg
 * @param {Buffer} leaf
 * @param {Buffer[]} branch
 * @param {Number} index
 * @returns {Buffer} root
 */

function deriveRoot(alg, leaf, branch, index) {
  assert(alg && typeof alg.multi === 'function');
  assert(Buffer.isBuffer(leaf));
  assert(Array.isArray(branch));
  assert((index >>> 0) === index);

  let root = hashLeaf(alg, leaf);

  for (const hash of branch) {
    if (index & 1)
      root = hashInternal(alg, hash, root);
    else
      root = hashInternal(alg, root, hash);

    index >>>= 1;
  }

  return root;
}

/**
 * Get sentinel hash.
 * @param {Object} alg
 * @returns {Buffer}
 */

function hashEmpty(alg) {
  return alg.digest(EMPTY);
}

/**
 * Hash a leaf node.
 * @param {Object} alg
 * @param {Buffer} data
 * @returns {Buffer}
 */

function hashLeaf(alg, data) {
  return alg.multi(LEAF, data);
}

/**
 * Hash an internal node.
 * @param {Object} alg
 * @param {Buffer} left
 * @param {Buffer} right
 * @returns {Buffer}
 */

function hashInternal(alg, left, right) {
  assert(right != null);
  return alg.multi(INTERNAL, left, right);
}

/*
 * Expose
 */

exports.createTree = createTree;
exports.createRoot = createRoot;
exports.createBranch = createBranch;
exports.deriveRoot = deriveRoot;
exports.hashEmpty = hashEmpty;
exports.hashLeaf = hashLeaf;
exports.hashInternal = hashInternal;
