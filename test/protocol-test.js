var assert = require('assert');
var bcoin = require('../');

describe('Protocol', function() {
  var parser;
  var framer;
  beforeEach(function() {
    parser = bcoin.protocol.parser();
    framer = bcoin.protocol.framer();
  });

  function packetTest(command, payload, test) {
    it('should encode/decode ' + command, function(cb) {
      var ver = framer[command]();
      parser.once('packet', function(packet) {
        assert.equal(packet.cmd, command);
        test(packet.payload);
        cb();
      });
      parser.feed(ver);
    });
  }

  packetTest('version', {}, function(payload) {
    assert.equal(payload.v, 70002);
    assert.equal(payload.relay, false);
  });

  packetTest('verack', {}, function(payload) {
  });
});
