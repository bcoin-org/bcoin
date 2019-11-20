'use strict';

describe('Exceptions', () => {
  it('should fail (setImmediate)', () => {
    setImmediate(() => {
      throw new Error('foobar 1');
    });
  });

  it('should not fail (setTimeout)', () => {
    setTimeout(() => {
      throw new Error('foobar 2');
    }, 1);
  });

  it('should fail (setTimeout async)', (cb) => {
    setTimeout(() => {
      throw new Error('foobar 3');
    }, 10);
    setTimeout(cb, 50);
  });
});
