'use strict';

describe('Swallow', () => {
  it('should warn', (cb) => {
    cb();
    throw new Error('foobar');
  });
});
