/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('assert');
const crypto = require('crypto');
const custom = require('util').inspect.custom || 'inspect';
const {BufferMap, BufferSet} = require('../');

describe('BufferMap', function() {
  it('should test map', () => {
    const map = new BufferMap();
    const keys = [];

    for (let i = 0; i < 10000; i++) {
      const key = crypto.randomBytes(32);
      map.set(key, i);
      keys.push(key);
    }

    assert(map.size === 10000);

    {
      const key = crypto.randomBytes(32);
      assert(map.has(key) === false);
      assert(map.get(key) === undefined);
    }

    for (let i = 0; i < 10000; i++) {
      assert(map.has(keys[i]) === true);
      const j = map.get(keys[i]);
      assert(j === i);
    }

    let i = 0;

    for (const [key, value] of map) {
      assert(key.equals(keys[i]));
      assert(value === i);
      i += 1;
    }

    i = 0;

    for (const [key, value] of map.entries()) {
      assert(key.equals(keys[i]));
      assert(value === i);
      i += 1;
    }

    i = 0;

    for (const key of map.keys()) {
      assert(key.equals(keys[i]));
      i += 1;
    }

    i = 0;

    for (const value of map.values()) {
      assert(value === i);
      i += 1;
    }

    i = 0;

    map.forEach(function(value, key, m) {
      assert(this === null);
      assert(m === map);
      assert(key.equals(keys[i]));
      assert(value === i);
      i += 1;
    }, null);

    assert.deepStrictEqual(map.toKeys(), keys);

    const values = [];

    for (let i = 0; i < 10000; i++)
      values.push(i);

    assert.deepStrictEqual(map.toValues(), values);
    assert.deepStrictEqual(map.toArray(), values);

    assert(map.has(keys[0]) === true);
    map.delete(keys[0]);
    assert(map.has(keys[0]) === false);
    assert(map.size === 9999);

    map.clear();

    for (const key of keys) {
      assert(map.has(key) === false);
      assert(map.get(key) === undefined);
    }

    assert(map.size === 0);

    {
      const key = crypto.randomBytes(32);
      const map = new BufferMap([[key, 0]]);

      assert.deepStrictEqual(map.toKeys(), [key]);
      assert.deepStrictEqual(map.toValues(), [0]);

      assert.deepStrictEqual(map[custom](),
        new Map([[key.toString('hex'), 0]]));

      const arr = new Uint8Array(key);

      assert(map.has(arr) === true);
      assert(map.has(arr.buffer) === true);

      arr[0] ^= 1;

      assert(map.has(arr) === false);
      assert(map.has(arr.buffer) === false);
    }
  });

  it('should test set', () => {
    const map = new BufferSet();
    const keys = [];

    for (let i = 0; i < 10000; i++) {
      const key = crypto.randomBytes(32);
      map.add(key);
      keys.push(key);
    }

    assert(map.size === 10000);

    {
      const key = crypto.randomBytes(32);
      assert(map.has(key) === false);
    }

    for (let i = 0; i < 10000; i++)
      assert(map.has(keys[i]) === true);

    let i = 0;

    for (const key of map) {
      assert(key.equals(keys[i]));
      i += 1;
    }

    i = 0;

    for (const [key, value] of map.entries()) {
      assert(key.equals(keys[i]));
      assert(value.equals(keys[i]));
      i += 1;
    }

    i = 0;

    for (const key of map.keys()) {
      assert(key.equals(keys[i]));
      i += 1;
    }

    i = 0;

    for (const value of map.values()) {
      assert(value.equals(keys[i]));
      i += 1;
    }

    i = 0;

    map.forEach(function(value, key, m) {
      assert(this === null);
      assert(m === map);
      assert(key.equals(keys[i]));
      assert(value.equals(keys[i]));
      i += 1;
    }, null);

    assert.deepStrictEqual(map.toKeys(), keys);
    assert.deepStrictEqual(map.toValues(), keys);
    assert.deepStrictEqual(map.toArray(), keys);

    assert(map.has(keys[0]) === true);
    map.delete(keys[0]);
    assert(map.has(keys[0]) === false);
    assert(map.size === 9999);

    map.clear();

    for (const key of keys)
      assert(map.has(key) === false);

    assert(map.size === 0);

    {
      const key = crypto.randomBytes(32);
      const map = new BufferSet([key]);

      assert.deepStrictEqual(map.toKeys(), [key]);
      assert.deepStrictEqual(map.toValues(), [key]);

      assert.deepStrictEqual(map[custom](),
        new Set([key.toString('hex')]));

      const arr = new Uint8Array(key);

      assert(map.has(arr) === true);
      assert(map.has(arr.buffer) === true);

      arr[0] ^= 1;

      assert(map.has(arr) === false);
      assert(map.has(arr.buffer) === false);
    }
  });
});
