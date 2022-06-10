'use strict';

const Golomb = require('./golomb');
const {U64} = require('n64');

class BasicFilter extends Golomb {
  constructor() {
    super();
    this.M = new U64(784931);
    this.m = this.M;
    this.p = 19;
  }
}

module.exports = BasicFilter;
