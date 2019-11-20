'use strict';

const assert = require('assert');

setTimeout(() => {
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

  run();
}, 500);
