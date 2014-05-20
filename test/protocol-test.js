var assert = require('assert');
var bcoin = require('../');
var utils = bcoin.utils;

describe('Protocol', function() {
  var parser;
  var framer;
  beforeEach(function() {
    parser = bcoin.protocol.parser();
    framer = bcoin.protocol.framer();
  });

  function packetTest(command, payload, test) {
    it('should encode/decode ' + command, function(cb) {
      var ver = framer[command](payload);
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

  var peers = [
    {
      ipv6: '0000:0000:0000:0000:0000:0000:0000:ffff',
      ipv4: '127.0.0.1',
      port: 8333,
      ts: Date.now() / 1000 | 0
    },
    {
      ipv6:  '0000:0000:0000:0000:0000:7f00:0001:ffff',
      ipv4: '10.0.0.1',
      port: 18333,
      ts: Date.now() / 1000 | 0
    }
  ];

  // Convert peers to framer payload format, backup strings.
  peers.forEach(function(addr) {
    addr._ipv4 = addr.ipv4;
    addr.ipv4 = addr.ipv4.split('.').map(function(n) {
      return +n;
    });
    addr._ipv6 = addr.ipv6;
    addr.ipv6 = utils.toArray(addr.ipv6, 'hex');
    addr._ipv6 = '::' + addr._ipv6.split(':').slice(2).join(':');
  });

  packetTest('addr', peers, function(payload) {
    assert.equal(typeof payload.length, 'number');
    assert.equal(payload.length, 2);

    assert.equal(typeof payload[0].ts, 'number');
    assert.equal(payload[0].service, 1);
    assert.equal(payload[0].ipv6, peers[0]._ipv6);
    assert.equal(payload[0].ipv4, peers[0]._ipv4);
    assert.equal(payload[0].port, peers[0].port);

    assert.equal(typeof payload[1].ts, 'number');
    assert.equal(payload[1].service, 1);
    assert.equal(payload[1].ipv6, peers[1]._ipv6);
    assert.equal(payload[1].ipv4, peers[1]._ipv4);
    assert.equal(payload[1].port, peers[1].port);
  });
});
