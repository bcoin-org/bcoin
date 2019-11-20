/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('bsert');
const SHA256 = require('../lib/sha256');
const merkle = require('../lib/merkle');
const random = require('../lib/random');

describe('Merkle', function() {
  it('should create perfect tree', () => {
    const leaves = [];

    for (let i = 0; i < 32; i++)
      leaves.push(random.randomBytes(32));

    const [tree, malleated] = merkle.createTree(SHA256, leaves.slice());

    assert(!malleated);

    const branch = merkle.createBranch(SHA256, 15, leaves);
    const root = merkle.deriveRoot(SHA256, leaves[15], branch, 15);

    assert.bufferEqual(root, tree[tree.length - 1]);
  });

  it('should create imperfect tree', () => {
    const leaves = [];

    for (let i = 0; i < 11; i++)
      leaves.push(random.randomBytes(32));

    const [tree, malleated] = merkle.createTree(SHA256, leaves.slice());

    assert(!malleated);

    const branch = merkle.createBranch(SHA256, 3, leaves);
    const root = merkle.deriveRoot(SHA256, leaves[3], branch, 3);

    assert.bufferEqual(root, tree[tree.length - 1]);
  });

  it('should detect malleation', () => {
    const leaves = [];

    for (let i = 0; i < 11; i++)
      leaves.push(random.randomBytes(32));

    let [, malleated] = merkle.createRoot(SHA256, leaves.slice());

    assert(!malleated);

    leaves.push(leaves[10]);

    [, malleated] = merkle.createRoot(SHA256, leaves.slice());

    assert(malleated);
  });
});
