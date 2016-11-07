'use strict';

var BN = require('bn.js');
var bcoin = require('../').set('regtest');
var constants = bcoin.constants;
var utils = bcoin.utils;
var crypto = require('../lib/crypto/crypto');
var assert = require('assert');
var opcodes = constants.opcodes;
var co = require('../lib/utils/co');
var cob = co.cob;

describe('Chain', function() {
  var node;

  it('should create node and add plugin', cob(function* () {
    node = new bcoin.fullnode({ db: 'memory' });
    node.on('error', function() {});
    node.use({
      name: 'foo',
      init: function(node) {
        var self = this;

        this.chain = node.require('chain');

        this.chain.on('block', function(block) {
          self.logger.info(block);
        });
      },
      open: function() {
        this.loaded = true;
        return Promise.resolve();
      },
      close: function() {
        this.loaded = false;
        return Promise.resolve();
      }
    });
    assert(node.plugins.foo);
    assert(!node.plugins.foo.loaded);
  }));

  it('should open node', cob(function* () {
    yield node.open();
    assert(node.plugins.foo.loaded);
  }));

  it('should close node', cob(function* () {
    yield node.close();
    assert(!node.plugins.foo.loaded);
  }));
});
