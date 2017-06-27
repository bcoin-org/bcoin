'use strict';

var assert = require('assert');
var secp256k1 = require('../lib/crypto/secp256k1');
var BIP150 = require('../lib/net/bip150');
var BIP151 = require('../lib/net/bip151');

describe('BIP150', function() {
  var db = new BIP150.AuthDB();
  var ck = secp256k1.generatePrivateKey();
  var sk = secp256k1.generatePrivateKey();

  db.addAuthorized(secp256k1.publicKeyCreate(ck, true));
  db.addKnown('127.0.0.2', secp256k1.publicKeyCreate(sk, true));

  var client = new BIP151();
  var server = new BIP151();

  client.bip150 = new BIP150(client, '127.0.0.2', true, db, ck);
  server.bip150 = new BIP150(server, '127.0.0.1', false, db, sk);

  function payload() {
    return Buffer.from('deadbeef', 'hex');
  }

  it('should do encinit', function() {
    var init = server.toEncinit();
    client.encinit(init.publicKey, init.cipher);

    init = client.toEncinit();
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
    var challenge, reply, propose, result;

    challenge = client.bip150.toChallenge();
    reply = server.bip150.challenge(challenge.hash);
    propose = client.bip150.reply(reply);
    challenge = server.bip150.propose(propose);
    reply = client.bip150.challenge(challenge);
    result = server.bip150.reply(reply);

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
