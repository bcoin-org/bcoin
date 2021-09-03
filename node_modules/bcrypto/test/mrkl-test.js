'use strict';

const assert = require('bsert');
const SHA256 = require('../lib/sha256');
const merkle = require('../lib/mrkl');

describe('Mrkl', function() {
  it('should create perfect tree', () => {
    const leaves = [];

    for (let i = 0; i < 32; i++)
      leaves.push(Buffer.alloc(32, i));

    const root1 = merkle.createRoot(SHA256, leaves);

    const branch = merkle.createBranch(SHA256, 15, leaves);
    const root2 = merkle.deriveRoot(SHA256, leaves[15], branch, 15);

    assert.bufferEqual(root2, root1);

    const branch3 = merkle.createBranch(SHA256, 31, leaves);
    const root3 = merkle.deriveRoot(SHA256, leaves[31], branch3, 31);

    assert.bufferEqual(root3, root1);
  });

  it('should create imperfect tree', () => {
    const leaves = [];

    for (let i = 0; i < 11; i++)
      leaves.push(Buffer.alloc(32, i));

    const root1 = merkle.createRoot(SHA256, leaves);

    const branch2 = merkle.createBranch(SHA256, 3, leaves);
    const root2 = merkle.deriveRoot(SHA256, leaves[3], branch2, 3);

    assert.bufferEqual(root2, root1);

    const branch3 = merkle.createBranch(SHA256, 10, leaves);
    const root3 = merkle.deriveRoot(SHA256, leaves[10], branch3, 10);

    assert.bufferEqual(root3, root1);
  });

  it('should not be malleable', () => {
    const leaves = [];

    for (let i = 0; i < 11; i++)
      leaves.push(Buffer.alloc(32, i));

    const root1 = merkle.createRoot(SHA256, leaves);

    leaves.push(leaves[10]);

    const root2 = merkle.createRoot(SHA256, leaves);

    assert.notBufferEqual(root2, root1);
  });

  it('should create perfect tree (8, 3)', () => {
    const leaves = [];

    for (let i = 0; i < 8; i++)
      leaves.push(Buffer.alloc(32, i));

    const root = merkle.createRoot(SHA256, leaves);
    const branch = merkle.createBranch(SHA256, 3, leaves);

    const a = merkle.hashLeaf(SHA256, leaves[0]);
    const b = merkle.hashLeaf(SHA256, leaves[1]);
    const c = merkle.hashLeaf(SHA256, leaves[2]);
    const d = merkle.hashLeaf(SHA256, leaves[3]);
    const e = merkle.hashLeaf(SHA256, leaves[4]);
    const f = merkle.hashLeaf(SHA256, leaves[5]);
    const g = merkle.hashLeaf(SHA256, leaves[6]);
    const h = merkle.hashLeaf(SHA256, leaves[7]);

    const i = merkle.hashInternal(SHA256, a, b);
    const j = merkle.hashInternal(SHA256, c, d);
    const k = merkle.hashInternal(SHA256, e, f);
    const l = merkle.hashInternal(SHA256, g, h);

    const m = merkle.hashInternal(SHA256, i, j);
    const n = merkle.hashInternal(SHA256, k, l);

    const o = merkle.hashInternal(SHA256, m, n);

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

    const root = merkle.createRoot(SHA256, leaves);
    const branch = merkle.createBranch(SHA256, 3, leaves);

    const a = merkle.hashLeaf(SHA256, leaves[0]);
    const b = merkle.hashLeaf(SHA256, leaves[1]);
    const c = merkle.hashLeaf(SHA256, leaves[2]);
    const d = merkle.hashLeaf(SHA256, leaves[3]);
    const e = merkle.hashLeaf(SHA256, leaves[4]);
    const f = merkle.hashLeaf(SHA256, leaves[5]);
    const g = merkle.hashLeaf(SHA256, leaves[6]);
    const h = merkle.hashEmpty(SHA256);

    const i = merkle.hashInternal(SHA256, a, b);
    const j = merkle.hashInternal(SHA256, c, d);
    const k = merkle.hashInternal(SHA256, e, f);
    const l = merkle.hashInternal(SHA256, g, h);

    const m = merkle.hashInternal(SHA256, i, j);
    const n = merkle.hashInternal(SHA256, k, l);

    const o = merkle.hashInternal(SHA256, m, n);

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

    const root = merkle.createRoot(SHA256, leaves);
    const branch = merkle.createBranch(SHA256, 6, leaves);

    const a = merkle.hashLeaf(SHA256, leaves[0]);
    const b = merkle.hashLeaf(SHA256, leaves[1]);
    const c = merkle.hashLeaf(SHA256, leaves[2]);
    const d = merkle.hashLeaf(SHA256, leaves[3]);
    const e = merkle.hashLeaf(SHA256, leaves[4]);
    const f = merkle.hashLeaf(SHA256, leaves[5]);
    const g = merkle.hashLeaf(SHA256, leaves[6]);
    const h = merkle.hashEmpty(SHA256);

    const i = merkle.hashInternal(SHA256, a, b);
    const j = merkle.hashInternal(SHA256, c, d);
    const k = merkle.hashInternal(SHA256, e, f);
    const l = merkle.hashInternal(SHA256, g, h);

    const m = merkle.hashInternal(SHA256, i, j);
    const n = merkle.hashInternal(SHA256, k, l);

    const o = merkle.hashInternal(SHA256, m, n);

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

    const root = merkle.createRoot(SHA256, leaves);
    const branch = merkle.createBranch(SHA256, 4, leaves);

    const a = merkle.hashLeaf(SHA256, leaves[0]);
    const b = merkle.hashLeaf(SHA256, leaves[1]);
    const c = merkle.hashLeaf(SHA256, leaves[2]);
    const d = merkle.hashLeaf(SHA256, leaves[3]);
    const e = merkle.hashLeaf(SHA256, leaves[4]);
    const f = merkle.hashLeaf(SHA256, leaves[5]);

    const g = merkle.hashInternal(SHA256, a, b);
    const h = merkle.hashInternal(SHA256, c, d);
    const i = merkle.hashInternal(SHA256, e, f);
    const j = merkle.hashEmpty(SHA256);

    const k = merkle.hashInternal(SHA256, g, h);
    const l = merkle.hashInternal(SHA256, i, j);

    const m = merkle.hashInternal(SHA256, k, l);

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
