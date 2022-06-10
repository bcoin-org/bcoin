'use strict';

const Golomb = require('./golomb');
const {U64} = require('n64');

class BasicFilter extends Golomb {
  constructor() {
    super();
    this.m = new U64(784931);
    this.p = 19;
  }
}

module.exports = BasicFilter;
