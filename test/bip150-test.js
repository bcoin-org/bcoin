/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('./util/assert');
const secp256k1 = require('../lib/crypto/secp256k1');
const BIP150 = require('../lib/net/bip150');
const BIP151 = require('../lib/net/bip151');

const db = new BIP150.AuthDB();
const ck = secp256k1.generatePrivateKey();
const sk = secp256k1.generatePrivateKey();

db.addAuthorized(secp256k1.publicKeyCreate(ck, true));
db.addKnown('127.0.0.2', secp256k1.publicKeyCreate(sk, true));

const client = new BIP151();
const server = new BIP151();

client.bip150 = new BIP150(client, '127.0.0.2', true, db, ck);
server.bip150 = new BIP150(server, '127.0.0.1', false, db, sk);

function payload() {
  return Buffer.from('deadbeef', 'hex');
}

describe('BIP150', function() {
  it('should do encinit', () => {
    const init = server.toEncinit();
    client.encinit(init.publicKey, init.cipher);

    const init2 = client.toEncinit();
    server.encinit(init2.publicKey, init2.cipher);

    assert(!client.handshake);
    assert(!server.handshake);
  });

  it('should do encack', () => {
    client.encack(server.toEncack().publicKey);
    server.encack(client.toEncack().publicKey);
    assert(client.handshake);
    assert(server.handshake);
  });

  it('should have completed ECDH handshake', () => {
    assert(client.isReady());
    assert(server.isReady());
    assert(client.handshake);
    assert(server.handshake);
  });

  it('should do BIP150 handshake', () => {
    const challenge = client.bip150.toChallenge();
    const reply = server.bip150.challenge(challenge.hash);
    const propose = client.bip150.reply(reply);
    const challenge2 = server.bip150.propose(propose);
    const reply2 = client.bip150.challenge(challenge2);
    const result = server.bip150.reply(reply2);

    assert(!result);
    assert(client.bip150.auth);
    assert(server.bip150.auth);
  });

  it('should encrypt payload from client to server', () => {
    const packet = client.packet('fake', payload());

    let emitted = false;
    server.once('packet', (cmd, body) => {
      emitted = true;
      assert.strictEqual(cmd, 'fake');
      assert.bufferEqual(body, payload());
    });

    server.feed(packet);

    assert(emitted);
  });

  it('should encrypt payload from server to client', () => {
    const packet = server.packet('fake', payload());

    let emitted = false;
    client.once('packet', (cmd, body) => {
      emitted = true;
      assert.strictEqual(cmd, 'fake');
      assert.bufferEqual(body, payload());
    });

    client.feed(packet);

    assert(emitted);
  });

  it('should encrypt payload from client to server (2)', () => {
    const packet = client.packet('fake', payload());

    let emitted = false;
    server.once('packet', (cmd, body) => {
      emitted = true;
      assert.strictEqual(cmd, 'fake');
      assert.bufferEqual(body, payload());
    });

    server.feed(packet);

    assert(emitted);
  });

  it('should encrypt payload from server to client (2)', () => {
    const packet = server.packet('fake', payload());

    let emitted = false;
    client.once('packet', (cmd, body) => {
      emitted = true;
      assert.strictEqual(cmd, 'fake');
      assert.bufferEqual(body, payload());
    });

    client.feed(packet);

    assert(emitted);
  });

  it('client should rekey', () => {
    const bytes = client.output.processed;
    let rekeyed = false;

    client.once('rekey', () => {
      rekeyed = true;
      const packet = client.packet('encack', client.toRekey().toRaw());
      let emitted = false;
      server.once('packet', (cmd, body) => {
        emitted = true;
        assert.strictEqual(cmd, 'encack');
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

  it('should encrypt payload from client to server after rekey', () => {
    const packet = client.packet('fake', payload());

    let emitted = false;
    server.once('packet', (cmd, body) => {
      emitted = true;
      assert.strictEqual(cmd, 'fake');
      assert.bufferEqual(body, payload());
    });

    server.feed(packet);

    assert(emitted);
  });

  it('should encrypt payload from server to client after rekey', () => {
    const packet = server.packet('fake', payload());

    let emitted = false;
    client.once('packet', (cmd, body) => {
      emitted = true;
      assert.strictEqual(cmd, 'fake');
      assert.bufferEqual(body, payload());
    });

    client.feed(packet);

    assert(emitted);
  });

  it('should encrypt payload from client to server after rekey (2)', () => {
    const packet = client.packet('fake', payload());

    let emitted = false;
    server.once('packet', (cmd, body) => {
      emitted = true;
      assert.strictEqual(cmd, 'fake');
      assert.bufferEqual(body, payload());
    });

    server.feed(packet);

    assert(emitted);
  });

  it('should encrypt payload from server to client after rekey (2)', () => {
    const packet = server.packet('fake', payload());

    let emitted = false;
    client.once('packet', (cmd, body) => {
      emitted = true;
      assert.strictEqual(cmd, 'fake');
      assert.bufferEqual(body, payload());
    });

    client.feed(packet);

    assert(emitted);
  });

  it('should encrypt payloads both ways asynchronously', () => {
    const spacket = server.packet('fake', payload());
    const cpacket = client.packet('fake', payload());

    let cemitted = false;
    client.once('packet', (cmd, body) => {
      cemitted = true;
      assert.strictEqual(cmd, 'fake');
      assert.bufferEqual(body, payload());
    });

    let semitted = false;
    server.once('packet', (cmd, body) => {
      semitted = true;
      assert.strictEqual(cmd, 'fake');
      assert.bufferEqual(body, payload());
    });

    client.feed(spacket);
    server.feed(cpacket);

    assert(cemitted);
    assert(semitted);
  });
});
