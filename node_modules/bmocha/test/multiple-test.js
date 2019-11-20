'use strict';

describe('Resolutions', () => {
  it('should fail (resolve & resolve)', () => {
    return new Promise((resolve, reject) => {
      resolve(1);
      resolve(2);
    });
  });

  it('should fail (resolve & reject)', () => {
    return new Promise((resolve, reject) => {
      resolve(3);
      reject(new Error('foobar'));
    });
  });

  it('should fail (resolve & throw)', () => {
    return new Promise((resolve, reject) => {
      resolve(4);
      throw new Error('foobar');
    });
  });
});
