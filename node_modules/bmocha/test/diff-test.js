'use strict';

const assert = require('assert');

describe('Diff', () => {
  it('should diff (1)', () => {
    assert.deepStrictEqual([
      'hello',
      'world',
      'foo',
      'bar',
      'baz'
    ], [
      'hello',
      'world',
      'foz',
      'bar',
      'baz'
    ]);
  });

  it('should diff (2)', () => {
    const a = Symbol('a');
    const b = Symbol('b');
    const c = Symbol('c');
    const d = new Date();
    assert.deepStrictEqual({
      hello: 1,
      world: 'a',
      foo: /bar/,
      'bar ': d,
      baz: 3,
      [b]: 1,
      [a]: 2
    }, {
      hello: 1,
      world: 'a',
      foz: /bar/,
      'bar ': d,
      baz: 3,
      [c]: 1,
      [a]: 2
    });
  });

  it('should diff (3)', () => {
    const d = new Date();
    assert.deepStrictEqual(new Map([
      ['hello', 1],
      ['world', 'a'],
      ['foo', /bar/],
      ['bar', d],
      ['baz', 3]
    ]), new Map([
      ['hello', 1],
      ['world', 'a'],
      ['foz', /bar/],
      ['bar', d],
      ['baz', 3]
    ]));
  });

  it('should diff (4)', () => {
    const d = new Date();
    assert.deepStrictEqual(new Set([
      1,
      'a',
      /bar/,
      d,
      3
    ]), new Set([
      2,
      'a',
      /bar/,
      d,
      3
    ]));
  });
});
