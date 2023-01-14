/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('bsert');
const Network = require('../lib/protocol/network');
const sinon = require('sinon');

describe('Network', function() {
  it('calling static create() with an object should cause an error ', () => {
    // See Issue #1126
    assert.throws(() => Network.create({}));
  });

  it('should return null from byBit() if its call to binary.search returns -1', () => {
    const binary = require('../lib/utils/binary');
    const network = Network.get('regtest');

    const stub = sinon.stub(binary, 'search').returns(-1);

    let result = network.byBit(0);

    assert.strictEqual(result, null);

    stub.restore();
  });

  it('should return the network time in milliseconds', () => {
    const network = Network.get('regtest');
    const time = network.ms();

    assert.strictEqual(typeof time, 'number');
  });

  it('should throw an error if get() is called with a param that is not a string or Network object', () => {
    assert.throws(() => {
      Network.get({});
    }, Error);
  });

  it('should return Network.primary if ensure() is called with no params', () => {
    const network = Network.get('regtest');
    Network.primary = network;

    const result = Network.ensure();

    assert.strictEqual(result, network);
  });

  it('should raise an assertion error if ensure() is called with undefined and Network.primary is undefined', () => {
    Network.primary = undefined;

    assert.throws(() => {
      Network.ensure();
    }, Error);
  });

  it('should return the network if ensure() is called with a Network object', () => {
    const network = Network.get('regtest');

    const result = Network.ensure(network);

    assert.strictEqual(result, network);
  });

  it('should create a network if we pass a string to ensure() and we have that network cached', () => {
    const result = Network.ensure('regtest');
    assert.strictEqual(result.type, 'regtest');
  });

  it('should raise an assertion error if ensure() is called with a string and we do not have that network cached', () => {
    assert.throws(() => {
      Network.ensure('unknownnetwork');
    }, Error);
  });

  it('should not raise an assertion error if ensure() is called with a string and we do not have that network cached, but Network.primary is set', () => {
    const network_primary = Network.get('regtest');
    Network.primary = network_primary;

    const result = Network.ensure('unknownnetwork');

    assert.strictEqual(result, network_primary);
  });

  it('should return Network.primary if it is set and we call ensure() with an object', () => {
    const network_primary = Network.get('regtest');
    Network.primary = network_primary;

    const result = Network.ensure({});

    assert.strictEqual(result, network_primary);
  });

  it('should return the type from toString()', () => {
    const network = Network.get('regtest');
    const result = network.toString();

    assert.strictEqual(result, 'regtest');
  });

  it('should return true from isNetwork() if we pass a Network object', () => {
    const network = Network.get('regtest');
    const result = Network.isNetwork(network);

    assert.strictEqual(result, true);
  });

  it('should return false from isNetwork() if we pass a string', () => {
    const result = Network.isNetwork('regtest');
    assert.strictEqual(result, false);
  });

  it('should return the appropriate string from inspectSymbol()', () => {
    const network = Network.get('regtest');
    const result = network[Symbol.for('nodejs.util.inspect.custom')]();

    assert.strictEqual(result, '<Network: regtest>');
  });
});
