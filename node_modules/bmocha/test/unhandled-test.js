'use strict';

describe('Rejections', () => {
  it('should fail (instant)', () => {
    new Promise((resolve, reject) => {
      reject(new Error('foobar 1'));
    });
  });

  it('should fail (setImmediate)', () => {
    setImmediate(() => {
      throw new Error('foobar 2');
    });
  });

  it('should not fail (setTimeout)', () => {
    setTimeout(() => {
      throw new Error('foobar 3');
    }, 1);
  });

  it('should fail (setTimeout async)', (cb) => {
    setTimeout(() => {
      new Promise((resolve, reject) => {
        reject(new Error('foobar 4'));
      });
    }, 10);
    setTimeout(cb, 50);
  });
});
