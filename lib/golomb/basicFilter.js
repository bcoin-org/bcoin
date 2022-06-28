'use strict';

const Golomb = require('./golomb');
const {U64} = require('n64');

class BasicFilter extends Golomb {
  constructor() {
    super(19, new U64(784931));
  }
}

module.exports = BasicFilter;
