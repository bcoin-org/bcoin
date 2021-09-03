'use strict';

const bench = require('./bench');
const crypto = require('crypto');
const random = require('../lib/random');

const rounds = 200000;

bench('randomBytes', rounds, () => {
  random.randomBytes(32);
});

bench('randomBytes (node)', rounds, () => {
  crypto.randomBytes(32);
});
