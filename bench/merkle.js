'use strict';

const assert = require('assert');
const merkle = require('../lib/crypto/merkle');
const random = require('../lib/crypto/random');
const bench = require('./bench');

const leaves = [];

for (let i = 0; i < 3000; i++)
  leaves.push(random.randomBytes(32));

{
  const end = bench('tree');
  for (let i = 0; i < 1000; i++) {
    const [n, m] = merkle.createTree(leaves.slice());
    assert(n);
    assert(!m);
  }
  end(1000);
}
