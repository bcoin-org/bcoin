'use strict';

const assert = require('assert');

const IS_MOCHA = Boolean(process.env.LOADED_MOCHA_OPTS);

describe('Fail', function() {
  describe('Assert', () => {
    it('should fail (assert)', () => {
      assert(false);
    });

    it('should fail (fail)', () => {
      assert.fail('foobar');
    });

    it('should fail (equal string)', () => {
      assert.equal('01020304', '010203');
    });

    it('should fail (not equal string)', () => {
      assert.notEqual('010203', '010203');
    });

    it('should fail (equal number)', () => {
      assert.equal(1, 2);
    });

    it('should fail (not equal number)', () => {
      assert.notEqual(1, 1);
    });

    it('should fail (strict equal string)', () => {
      assert.strictEqual('01020304', '010203');
    });

    it('should fail (not strict equal string)', () => {
      assert.notStrictEqual('010203', '010203');
    });

    it('should fail (strict equal number)', () => {
      assert.strictEqual(1, 2);
    });

    it('should fail (not strict equal number)', () => {
      assert.notStrictEqual(1, 1);
    });

    it('should fail (deep equal string)', () => {
      assert.deepStrictEqual('01020304', '010203');
    });

    it('should fail (not deep equal string)', () => {
      assert.notDeepStrictEqual('010203', '010203');
    });

    it('should fail (deep equal number)', () => {
      assert.deepStrictEqual(1, 2);
    });

    it('should fail (not deep equal number)', () => {
      assert.notDeepStrictEqual(1, 1);
    });

    it('should fail (strict equal object)', () => {
      const makeObj = () => {
        const now = 1544200539595;
        return {
          undef: undefined,
          nil: null,
          nan: NaN,
          inf: Infinity,
          ninf: -Infinity,
          error: new Error('foo'),
          number: 1,
          string: 'foo',
          buffer: Buffer.from([1, 2, 3]),
          time: new Date(now),
          regex: /hello/,
          arraybuffer: new Uint8Array([1, 2, 3]).buffer,
          uint8array: new Uint8Array([1, 2, 3]),
          float32array: new Float32Array([1, 2, 3]),
          args: arguments,
          map: new Map([[1, 'a'], [2, 'b'], [3, 'c']]),
          map2:
            new Map([[{foo:1}, 'bar'], [/foo/, 'bar'], ['spaced key', 100]]),
          'spaced key': 100,
          set: new Set([1, 2, 3]),
          array: [1, 2, 3],
          object: { a: 1, b: 2, c: 3 }
        };
      };

      const a = makeObj();
      const b = makeObj();

      delete a.args;
      delete a.map2;

      delete b.args;
      delete b.map2;

      a.number = 0;
      a.z = 1;

      assert.deepStrictEqual(a, b);
    });

    it('should fail (not strict equal)', () => {
      const makeObj = () => {
        const now = 1544200539595;
        return {
          undef: undefined,
          nil: null,
          nan: NaN,
          inf: Infinity,
          ninf: -Infinity,
          error: new Error('foo'),
          number: 1,
          string: 'foo',
          buffer: Buffer.from([1, 2, 3]),
          time: new Date(now),
          regex: /hello/,
          arraybuffer: new Uint8Array([1, 2, 3]).buffer,
          uint8array: new Uint8Array([1, 2, 3]),
          float32array: new Float32Array([1, 2, 3]),
          args: arguments,
          map: new Map([[1, 'a'], [2, 'b'], [3, 'c']]),
          map2:
            new Map([[{foo:1}, 'bar'], [/foo/, 'bar'], ['spaced key', 100]]),
          'spaced key': 100,
          set: new Set([1, 2, 3]),
          array: [1, 2, 3],
          object: { a: 1, b: 2, c: 3 }
        };
      };

      const a = makeObj();
      const b = makeObj();

      delete a.args;
      delete a.nan;
      delete a.map2;

      delete b.args;
      delete b.nan;
      delete b.map2;

      assert.notDeepStrictEqual(a, b);
    });

    it('should fail (throws)', () => {
      assert.throws(() => {});
    });

    if (assert.rejects) {
      it('should fail (rejects)', async () => {
        await assert.rejects(async () => {});
      });
    }

    if (assert.bufferEqual) {
      it('should fail (buffer equal)', () => {
        assert.bufferEqual(Buffer.from('01020304', 'hex'), '010203');
      });

      it('should fail (not buffer equal)', () => {
        assert.notBufferEqual(Buffer.from('010203', 'hex'), '010203');
      });
    }

    it('should fail (assert)', async () => {
      assert(false);
    });

    it('should fail (fail)', async () => {
      assert.fail('foobar');
    });

    it('should fail (equal string)', async () => {
      assert.equal('01020304', '010203');
    });

    it('should fail (not equal string)', async () => {
      assert.notEqual('010203', '010203');
    });

    it('should fail (equal number)', async () => {
      assert.equal(1, 2);
    });

    it('should fail (not equal number)', async () => {
      assert.notEqual(1, 1);
    });

    it('should fail (strict equal string)', async () => {
      assert.strictEqual('01020304', '010203');
    });

    it('should fail (not strict equal string)', async () => {
      assert.notStrictEqual('010203', '010203');
    });

    it('should fail (strict equal number)', async () => {
      assert.strictEqual(1, 2);
    });

    it('should fail (not strict equal number)', async () => {
      assert.notStrictEqual(1, 1);
    });

    it('should fail (deep equal string)', async () => {
      assert.deepStrictEqual('01020304', '010203');
    });

    it('should fail (not deep equal string)', async () => {
      assert.notDeepStrictEqual('010203', '010203');
    });

    it('should fail (deep equal number)', async () => {
      assert.deepStrictEqual(1, 2);
    });

    it('should fail (not deep equal number)', async () => {
      assert.notDeepStrictEqual(1, 1);
    });
  });

  describe('Mocha', () => {
    it('should fail (double call)', (cb) => {
      setImmediate(cb);
      setImmediate(cb);
    });

    it('should fail (overspecified promise)', (cb) => {
      return Promise.resolve();
    });

    it('should fail (timeout cb)', (cb) => {
      assert(1);
    });

    it('should fail (overspecified async func)', async (cb) => {
      assert(1);
    });

    // These break mocha:
    if (!IS_MOCHA) {
      it('should fail (throwing and catching uncaught error)', () => {
        setImmediate(() => {
          throw new Error('foobar 1');
        });
      });

      it('should not fail (throwing uncaught error)', () => {
        setTimeout(() => {
          throw new Error('foobar 2');
        }, 1);
      });

      it('should fail (catching uncaught error)', () => {
        ;
      });
    }

    it('should fail (uncaught error)', (cb) => {
      setTimeout(() => {
        throw new Error('foobar 3');
      }, 10);
      setTimeout(cb, 50);
    });

    it('should fail (unhandled rejection)', (cb) => {
      setTimeout(() => {
        new Promise((resolve, reject) => {
          reject(new Error('foobar 4'));
        });
      }, 10);
      setTimeout(cb, 50);
    });

    it('should fail (multiple resolves)', (cb) => {
      setTimeout(() => {
        new Promise((resolve, reject) => {
          resolve(1);
          resolve(2);
        });
      }, 10);
      setTimeout(cb, 50);
    });

    it('should fail (resolve & resolve)', () => {
      return new Promise((resolve, reject) => {
        resolve(3);
        resolve(4);
      });
    });

    it('should fail (resolve & reject)', () => {
      return new Promise((resolve, reject) => {
        resolve(5);
        reject(new Error('foobar'));
      });
    });

    it('should fail (no resolve / throw)', () => {
      return new Promise((resolve, reject) => {
        throw new Error('foobar');
      });
    });

    it('should fail (resolve & throw)', () => {
      return new Promise((resolve, reject) => {
        resolve(6);
        throw new Error('foobar');
      });
    });
  });

  describe('Misc', () => {
    it('should fail (error)', () => {
      throw new Error('Just an error.');
    });

    it('should fail (non-error)', () => {
      throw 'foobar';
    });

    it('should fail (non-error)', () => {
      throw /foobar/;
    });
  });

  describe('Hook 1', () => {
    before(() => {
      assert(false);
    });

    it('should not be executed', () => {
      assert(1);
    });
  });

  describe('Hook 2', () => {
    before('named hook', () => {
      assert(false);
    });

    it('should not be executed', () => {
      assert(1);
    });
  });

  describe('Hook 3', () => {
    beforeEach(() => {
      assert(false);
    });

    it('should not be executed', () => {
      assert(1);
    });
  });

  describe('Hook 4', () => {
    beforeEach('named hook', () => {
      assert(false);
    });

    it('should not be executed', () => {
      assert(1);
    });
  });
});
