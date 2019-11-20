'use strict';

const assert = require('assert');
const {describe, it} = require('../');

describe('Suite 1', () => {
  it('should run test', () => {
    assert(1 === 1);
  });

  describe('Suite 2', () => {
    it('should fail running other test', () => {
      global.foo = 1;
    });

    it('should not fail running other test', () => {
      delete global.foo;
    });

    it('should fail running other test', () => {
      global.foo = 1;
    });
  });
});
