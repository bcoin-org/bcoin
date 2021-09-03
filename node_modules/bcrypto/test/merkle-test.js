'use strict';

const assert = require('bsert');
const SHA256 = require('../lib/sha256');
const merkle = require('../lib/merkle');

describe('Merkle', function() {
  it('should create perfect tree', () => {
    const leaves = [];

    for (let i = 0; i < 32; i++)
      leaves.push(Buffer.alloc(32, i));

    const [tree, malleated] = merkle.createTree(SHA256, leaves);

    assert(!malleated);

    const branch = merkle.createBranch(SHA256, 15, leaves);
    const root = merkle.deriveRoot(SHA256, leaves[15], branch, 15);

    assert.bufferEqual(root, tree[tree.length - 1]);

    const branch2 = merkle.createBranch(SHA256, 31, leaves);
    const root2 = merkle.deriveRoot(SHA256, leaves[31], branch2, 31);

    assert.bufferEqual(root2, tree[tree.length - 1]);
  });

  it('should create imperfect tree', () => {
    const leaves = [];

    for (let i = 0; i < 11; i++)
      leaves.push(Buffer.alloc(32, i));

    const [tree, malleated] = merkle.createTree(SHA256, leaves);

    assert(!malleated);

    const branch = merkle.createBranch(SHA256, 3, leaves);
    const root = merkle.deriveRoot(SHA256, leaves[3], branch, 3);

    assert.bufferEqual(root, tree[tree.length - 1]);

    const branch2 = merkle.createBranch(SHA256, 10, leaves);
    const root2 = merkle.deriveRoot(SHA256, leaves[10], branch2, 10);

    assert.bufferEqual(root2, tree[tree.length - 1]);
  });

  it('should detect malleation', () => {
    const leaves = [];

    for (let i = 0; i < 11; i++)
      leaves.push(Buffer.alloc(32, i));

    let [, malleated] = merkle.createRoot(SHA256, leaves);

    assert(!malleated);

    leaves.push(leaves[10]);

    [, malleated] = merkle.createRoot(SHA256, leaves);

    assert(malleated);
  });

  it('should create perfect tree (8, 3)', () => {
    const leaves = [];

    for (let i = 0; i < 8; i++)
      leaves.push(Buffer.alloc(32, i));

    const [root] = merkle.createRoot(SHA256, leaves);
    const branch = merkle.createBranch(SHA256, 3, leaves);

    const a = leaves[0];
    const b = leaves[1];
    const c = leaves[2];
    const d = leaves[3];
    const e = leaves[4];
    const f = leaves[5];
    const g = leaves[6];
    const h = leaves[7];

    const i = SHA256.root(a, b);
    const j = SHA256.root(c, d);
    const k = SHA256.root(e, f);
    const l = SHA256.root(g, h);

    const m = SHA256.root(i, j);
    const n = SHA256.root(k, l);

    const o = SHA256.root(m, n);

    assert.bufferEqual(root, o);
    assert.deepStrictEqual(branch, [c, i, n]);
    assert.bufferEqual(merkle.deriveRoot(SHA256, leaves[3], branch, 3), root);

    assert.deepStrictEqual(merkle.createBranch(SHA256, 0, leaves), [b, j, n]);
    assert.deepStrictEqual(merkle.createBranch(SHA256, 1, leaves), [a, j, n]);
    assert.deepStrictEqual(merkle.createBranch(SHA256, 2, leaves), [d, i, n]);
    assert.deepStrictEqual(merkle.createBranch(SHA256, 3, leaves), [c, i, n]);
    assert.deepStrictEqual(merkle.createBranch(SHA256, 4, leaves), [f, l, m]);
    assert.deepStrictEqual(merkle.createBranch(SHA256, 5, leaves), [e, l, m]);
    assert.deepStrictEqual(merkle.createBranch(SHA256, 6, leaves), [h, k, m]);
    assert.deepStrictEqual(merkle.createBranch(SHA256, 7, leaves), [g, k, m]);

    for (let i = 0; i < 3; i++)
      assert.notBufferEqual(merkle.deriveRoot(SHA256, leaves[3], branch, i), root);

    for (let i = 4; i < 11; i++)
      assert.notBufferEqual(merkle.deriveRoot(SHA256, leaves[3], branch, i), root);
  });

  it('should create imperfect tree (7, 3)', () => {
    const leaves = [];

    for (let i = 0; i < 7; i++)
      leaves.push(Buffer.alloc(32, i));

    const [root] = merkle.createRoot(SHA256, leaves);
    const branch = merkle.createBranch(SHA256, 3, leaves);

    const a = leaves[0];
    const b = leaves[1];
    const c = leaves[2];
    const d = leaves[3];
    const e = leaves[4];
    const f = leaves[5];
    const g = leaves[6];
    const h = g;

    const i = SHA256.root(a, b);
    const j = SHA256.root(c, d);
    const k = SHA256.root(e, f);
    const l = SHA256.root(g, h);

    const m = SHA256.root(i, j);
    const n = SHA256.root(k, l);

    const o = SHA256.root(m, n);

    assert.bufferEqual(root, o);
    assert.deepStrictEqual(branch, [c, i, n]);
    assert.bufferEqual(merkle.deriveRoot(SHA256, leaves[3], branch, 3), root);

    assert.deepStrictEqual(merkle.createBranch(SHA256, 0, leaves), [b, j, n]);
    assert.deepStrictEqual(merkle.createBranch(SHA256, 1, leaves), [a, j, n]);
    assert.deepStrictEqual(merkle.createBranch(SHA256, 2, leaves), [d, i, n]);
    assert.deepStrictEqual(merkle.createBranch(SHA256, 3, leaves), [c, i, n]);
    assert.deepStrictEqual(merkle.createBranch(SHA256, 4, leaves), [f, l, m]);
    assert.deepStrictEqual(merkle.createBranch(SHA256, 5, leaves), [e, l, m]);
    assert.deepStrictEqual(merkle.createBranch(SHA256, 6, leaves), [h, k, m]);

    for (let i = 0; i < 3; i++)
      assert.notBufferEqual(merkle.deriveRoot(SHA256, leaves[3], branch, i), root);

    for (let i = 4; i < 10; i++)
      assert.notBufferEqual(merkle.deriveRoot(SHA256, leaves[3], branch, i), root);
  });

  it('should create imperfect tree (7, 6)', () => {
    const leaves = [];

    for (let i = 0; i < 7; i++)
      leaves.push(Buffer.alloc(32, i));

    const [root] = merkle.createRoot(SHA256, leaves);
    const branch = merkle.createBranch(SHA256, 6, leaves);

    const a = leaves[0];
    const b = leaves[1];
    const c = leaves[2];
    const d = leaves[3];
    const e = leaves[4];
    const f = leaves[5];
    const g = leaves[6];
    const h = g;

    const i = SHA256.root(a, b);
    const j = SHA256.root(c, d);
    const k = SHA256.root(e, f);
    const l = SHA256.root(g, h);

    const m = SHA256.root(i, j);
    const n = SHA256.root(k, l);

    const o = SHA256.root(m, n);

    assert.bufferEqual(root, o);
    assert.deepStrictEqual(branch, [h, k, m]);
    assert.bufferEqual(merkle.deriveRoot(SHA256, leaves[6], branch, 6), root);

    assert.deepStrictEqual(merkle.createBranch(SHA256, 0, leaves), [b, j, n]);
    assert.deepStrictEqual(merkle.createBranch(SHA256, 1, leaves), [a, j, n]);
    assert.deepStrictEqual(merkle.createBranch(SHA256, 2, leaves), [d, i, n]);
    assert.deepStrictEqual(merkle.createBranch(SHA256, 3, leaves), [c, i, n]);
    assert.deepStrictEqual(merkle.createBranch(SHA256, 4, leaves), [f, l, m]);
    assert.deepStrictEqual(merkle.createBranch(SHA256, 5, leaves), [e, l, m]);
    assert.deepStrictEqual(merkle.createBranch(SHA256, 6, leaves), [h, k, m]);

    for (let i = 0; i < 6; i++)
      assert.notBufferEqual(merkle.deriveRoot(SHA256, leaves[6], branch, i), root);

    for (let i = 7; i < 10; i++)
      assert.notBufferEqual(merkle.deriveRoot(SHA256, leaves[6], branch, i), root);
  });

  it('should create imperfect tree (6, 4)', () => {
    const leaves = [];

    for (let i = 0; i < 6; i++)
      leaves.push(Buffer.alloc(32, i));

    const [root] = merkle.createRoot(SHA256, leaves);
    const branch = merkle.createBranch(SHA256, 4, leaves);

    const a = leaves[0];
    const b = leaves[1];
    const c = leaves[2];
    const d = leaves[3];
    const e = leaves[4];
    const f = leaves[5];

    const g = SHA256.root(a, b);
    const h = SHA256.root(c, d);
    const i = SHA256.root(e, f);
    const j = i;

    const k = SHA256.root(g, h);
    const l = SHA256.root(i, j);

    const m = SHA256.root(k, l);

    assert.bufferEqual(root, m);
    assert.deepStrictEqual(branch, [f, j, k]);
    assert.bufferEqual(merkle.deriveRoot(SHA256, leaves[4], branch, 4), root);

    assert.deepStrictEqual(merkle.createBranch(SHA256, 0, leaves), [b, h, l]);
    assert.deepStrictEqual(merkle.createBranch(SHA256, 1, leaves), [a, h, l]);
    assert.deepStrictEqual(merkle.createBranch(SHA256, 2, leaves), [d, g, l]);
    assert.deepStrictEqual(merkle.createBranch(SHA256, 3, leaves), [c, g, l]);
    assert.deepStrictEqual(merkle.createBranch(SHA256, 4, leaves), [f, j, k]);
    assert.deepStrictEqual(merkle.createBranch(SHA256, 5, leaves), [e, j, k]);

    for (let i = 0; i < 4; i++)
      assert.notBufferEqual(merkle.deriveRoot(SHA256, leaves[4], branch, i), root);

    for (let i = 5; i < 9; i++)
      assert.notBufferEqual(merkle.deriveRoot(SHA256, leaves[4], branch, i), root);
  });
});
