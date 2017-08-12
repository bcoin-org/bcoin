/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('./util/assert');
const BIP151 = require('../lib/net/bip151');

const client = new BIP151();
const server = new BIP151();

function payload() {
  return Buffer.from('deadbeef', 'hex');
}

describe('BIP151', function() {
  it('should do encinit', () => {
    let init = server.toEncinit();
    client.encinit(init.publicKey, init.cipher);

    init = client.toEncinit();
    server.encinit(init.publicKey, init.cipher);

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
