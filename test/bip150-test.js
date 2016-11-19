'use strict';

var BN = require('bn.js');
var bcoin = require('../').set('main');
var util = bcoin.util;
var crypto = require('../lib/crypto/crypto');
var constants = bcoin.constants;
var network = bcoin.networks;
var assert = require('assert');

describe('BIP150', function() {
  var db = new bcoin.bip150.AuthDB();
  var ck = bcoin.ec.generatePrivateKey();
  var sk = bcoin.ec.generatePrivateKey();

  db.addAuthorized(bcoin.ec.publicKeyCreate(ck, true));
  db.addKnown('server', bcoin.ec.publicKeyCreate(sk, true));

  var client = new bcoin.bip151();
  var server = new bcoin.bip151();

  client.bip150 = new bcoin.bip150(client, 'server', true, db, ck);
  server.bip150 = new bcoin.bip150(server, 'client', false, db, sk);

  function payload() {
    return new Buffer('deadbeef', 'hex');
  }

  it('should do encinit', function() {
    var init = server.toEncinit();
    client.encinit(init.publicKey, init.cipher);
    var init = client.toEncinit();
    server.encinit(init.publicKey, init.cipher);
    assert(!client.handshake);
    assert(!server.handshake);
  });

  it('should do encack', function() {
    client.encack(server.toEncack().publicKey);
    server.encack(client.toEncack().publicKey);
    assert(client.handshake);
    assert(server.handshake);
  });

  it('should have completed ECDH handshake', function() {
    assert(client.isReady());
    assert(server.isReady());
    assert(client.handshake);
    assert(server.handshake);
  });

  it('should do BIP150 handshake', function() {
    var challenge = client.bip150.toChallenge();
    var reply = server.bip150.challenge(challenge.hash);
    var propose = client.bip150.reply(reply);
    var challenge = server.bip150.propose(propose);
    var reply = client.bip150.challenge(challenge);
    var result = server.bip150.reply(reply);
    assert(!result);
    assert(client.bip150.auth);
    assert(server.bip150.auth);
  });

  it('should encrypt payload from client to server', function() {
    var packet = client.packet('fake', payload());
    var emitted = false;
    server.once('packet', function(cmd, body) {
      emitted = true;
      assert.equal(cmd, 'fake');
      assert.equal(body.toString('hex'), 'deadbeef');
    });
    server.feed(packet);
    assert(emitted);
  });

  it('should encrypt payload from server to client', function() {
    var packet = server.packet('fake', payload());
    var emitted = false;
    client.once('packet', function(cmd, body) {
      emitted = true;
      assert.equal(cmd, 'fake');
      assert.equal(body.toString('hex'), 'deadbeef');
    });
    client.feed(packet);
    assert(emitted);
  });

  it('should encrypt payload from client to server (2)', function() {
    var packet = client.packet('fake', payload());
    var emitted = false;
    server.once('packet', function(cmd, body) {
      emitted = true;
      assert.equal(cmd, 'fake');
      assert.equal(body.toString('hex'), 'deadbeef');
    });
    server.feed(packet);
    assert(emitted);
  });

  it('should encrypt payload from server to client (2)', function() {
    var packet = server.packet('fake', payload());
    var emitted = false;
    client.once('packet', function(cmd, body) {
      emitted = true;
      assert.equal(cmd, 'fake');
      assert.equal(body.toString('hex'), 'deadbeef');
    });
    client.feed(packet);
    assert(emitted);
  });

  it('client should rekey', function() {
    var rekeyed = false;
    var bytes = client.output.processed;

    client.once('rekey', function() {
      rekeyed = true;
      var packet = client.packet('encack', client.toRekey().toRaw());
      var emitted = false;
      server.once('packet', function(cmd, body) {
        emitted = true;
        assert.equal(cmd, 'encack');
        server.encack(body);
      });
      server.feed(packet);
      assert(emitted);
    });

    // Force a rekey after 1gb processed.
    client.maybeRekey({ length: 1024 * (1 << 20) });

    assert(rekeyed);

    // Reset so as not to mess up
    // the symmetry of client and server.
    client.output.processed = bytes + 33 + 31;
  });

  it('should encrypt payload from client to server after rekey', function() {
    var packet = client.packet('fake', payload());
    var emitted = false;
    server.once('packet', function(cmd, body) {
      emitted = true;
      assert.equal(cmd, 'fake');
      assert.equal(body.toString('hex'), 'deadbeef');
    });
    server.feed(packet);
    assert(emitted);
  });

  it('should encrypt payload from server to client after rekey', function() {
    var packet = server.packet('fake', payload());
    var emitted = false;
    client.once('packet', function(cmd, body) {
      emitted = true;
      assert.equal(cmd, 'fake');
      assert.equal(body.toString('hex'), 'deadbeef');
    });
    client.feed(packet);
    assert(emitted);
  });

  it('should encrypt payload from client to server after rekey (2)', function() {
    var packet = client.packet('fake', payload());
    var emitted = false;
    server.once('packet', function(cmd, body) {
      emitted = true;
      assert.equal(cmd, 'fake');
      assert.equal(body.toString('hex'), 'deadbeef');
    });
    server.feed(packet);
    assert(emitted);
  });

  it('should encrypt payload from server to client after rekey (2)', function() {
    var packet = server.packet('fake', payload());
    var emitted = false;
    client.once('packet', function(cmd, body) {
      emitted = true;
      assert.equal(cmd, 'fake');
      assert.equal(body.toString('hex'), 'deadbeef');
    });
    client.feed(packet);
    assert(emitted);
  });

  it('should encrypt payloads both ways asynchronously', function() {
    var spacket = server.packet('fake', payload());
    var cpacket = client.packet('fake', payload());
    var cemitted = false;
    var semitted = false;
    client.once('packet', function(cmd, body) {
      cemitted = true;
      assert.equal(cmd, 'fake');
      assert.equal(body.toString('hex'), 'deadbeef');
    });
    server.once('packet', function(cmd, body) {
      semitted = true;
      assert.equal(cmd, 'fake');
      assert.equal(body.toString('hex'), 'deadbeef');
    });
    client.feed(spacket);
    server.feed(cpacket);
    assert(cemitted);
    assert(semitted);
  });
});
