'use strict';

const assert = require('assert');

describe('Mocha 1', function() {
  this.timeout(120000);

  let x = 0;
  let y = 0;

  beforeEach(() => {
    x += 1;
  });

  afterEach(() => {
    x += 1;
  });

  before(() => {
    y = 1;
  });

  after(() => {
    y = 0;
  });

  it('should succeed', () => {
    assert.strictEqual(x, 1);
    assert.strictEqual(y, 1);
    assert.strictEqual(1, 1);
  });

  it('should fail (randomly)', () => {
    if (Math.random() < 0.30)
      assert.strictEqual(0, 1);
  });

  it('should take a while (1)', async () => {
    assert.strictEqual(x, 5);
    await new Promise(r => setTimeout(r, 40));
  });

  it('should take a while (2)', async () => {
    assert.strictEqual(x, 7);
    await new Promise(r => setTimeout(r, 130));
  });

  it('should take a while (3)', (cb) => {
    this.timeout(2000);
    assert.strictEqual(x, 9);
    setTimeout(cb, 30);
  });

  describe('Mocha 2', function() {
    this.timeout(2000);

    after(() => {
      x = 1;
    });

    it('should succeed', () => {
      assert.strictEqual(x, 13);
      assert.strictEqual(y, 1);
      assert.strictEqual(1, 1);
    });

    it('should fail (randomly)', () => {
      if (Math.random() < 0.30)
        assert.strictEqual(0, 1);
    });
  });

  it('should happen before describe', () => {
    assert.strictEqual(x, 11);
  });
});

describe('Mocha 3', function() {
  it('should skip', function() {
    this.skip();
    assert.strictEqual(0, 1);
  });

  it('should not skip', function() {
    assert.strictEqual(1, 1);
  });
});
