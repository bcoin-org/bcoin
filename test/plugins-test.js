'use strict';

var bcoin = require('../').set('regtest');
var assert = require('assert');
var utils = require('../lib/utils');
var co = require('../lib/utils/co');
var cob = co.cob;

describe('Plug-ins', function() {
  var nopp, node, plugin;

  nopp = function(node) {
    return Promise.resolve(node);
  };

  node = new bcoin.fullnode({ db: 'memory' });
  plugin = { open: nopp, close: nopp };

  it('should attach a simplified plug-in', function() {
		var attached = node.attach(nopp);
    assert.deepEqual({ open: nopp, close: attached.close }, attached);
  });

  it('should attach a standard plug-in', function() {
    var attached = node.attach(plugin);
    assert.deepEqual(plugin, attached);
  });

  it('should bind the plug-in methods to the node', cob(function* () {
    var called, arg;
    node.attach(function(node) {
      called = true;
      arg = node;
      return Promise.resolve();
    });
    yield node.open();
    assert(called);
    assert.deepEqual(arg, node);
  }));

  it('should trigger the plug-in close method on node close', cob(function* () {
    var called, arg;
    node.attach({
      close: function(node) {
        called = true;
        arg = node;
        return Promise.resolve();
      }
    });
    yield node.close();
    assert(called);
    assert.deepEqual(arg, node);
  }));

  it('should not accept plug-in not implementing base methods', function() {
    assert.throws(function() {
      node.attach({ nonBaseMethod: nopp });
    }, assert.AssertionError);
  });

  it('should handle exceptions gracefully', cob(function* () {
    assert.doesNotThrow(function() {
      node.attach({
        close: function() {
          return Promise.resolve().then(function() {
            throw new Error('Plug-in failure')
          })
        }
      });
    });
    yield node.open();
  }));

  it('should cleanup', cob(function* () {
    yield node.close();
  }));
});
