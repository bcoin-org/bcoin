'use strict';

const assert = require('assert');
const {describe, it} = require('../');

describe('Suite 1', () => {
  it('should run test', () => {
    assert(1 === 1);
  });

  describe('Suite 2', () => {
    it('should run other test', () => {
      assert(2 === 2);
    });
  });
});
