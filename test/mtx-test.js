/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('bsert');
const MTX = require('../lib/primitives/mtx');
const KeyRing = require('../lib/primitives/keyring');
const Address = require('../lib/primitives/address');
const Script = require('../lib/script/script');
const Coin = require('../lib/primitives/coin');

describe('MTX', function() {
  describe('Estimate Size', function() {
    for (let ins = 1; ins <= 10; ins++) {
      it(`P2PK ${ins}-in 1-out`, async () => {
        const ring = KeyRing.generate();
        const script = Script.fromPubkey(ring.publicKey);

        const mtx = new MTX();

        for (let i = 1; i <= ins; i++) {
          const coin = new Coin({
            version: 1,
            height: 1,
            value: 10000,
            script: script,
            coinbase: false,
            hash: Buffer.alloc(32),
            index: 0
          });
          mtx.addCoin(coin);
        }

        mtx.addOutput({
          address: new Address(),
          value: 9000
        });
        const estSize = await mtx.estimateSize();

        mtx.sign(ring);
        const tx = mtx.toTX();
        assert(tx.verify(mtx.view));
        const actualSize = tx.getVirtualSize();

        assert(estSize >= actualSize);
      });

      it(`P2PKH ${ins}-in 1-out`, async () => {
        const ring = KeyRing.generate();
        const script = Script.fromPubkeyhash(ring.getKeyHash());

        const mtx = new MTX();

        for (let i = 1; i <= ins; i++) {
          const coin = new Coin({
            version: 1,
            height: 1,
            value: 10000,
            script: script,
            coinbase: false,
            hash: Buffer.alloc(32),
            index: 0
          });

          mtx.addCoin(coin);
        }

        mtx.addOutput({
          address: new Address(),
          value: 9000
        });
        const estSize = await mtx.estimateSize();

        mtx.sign(ring);
        const tx = mtx.toTX();
        assert(tx.verify(mtx.view));
        const actualSize = tx.getVirtualSize();

        assert(estSize >= actualSize);
      });

      it(`Bare 2-of-3 Multisig ${ins}-in 1-out`, async () => {
        const ring1 = KeyRing.generate();
        const ring2 = KeyRing.generate();
        const ring3 = KeyRing.generate();
        const script = Script.fromMultisig(2, 3,
          [
            ring1.publicKey,
            ring2.publicKey,
            ring3.publicKey
          ]);

        const mtx = new MTX();

        for (let i = 1; i <= ins; i++) {
          const coin = new Coin({
            version: 1,
            height: 1,
            value: 10000,
            script: script,
            coinbase: false,
            hash: Buffer.alloc(32),
            index: 0
          });

          mtx.addCoin(coin);
        }

        mtx.addOutput({
          address: new Address(),
          value: 9000
        });
        const estSize = await mtx.estimateSize();

        ring1.script = script;
        ring2.script = script;
        mtx.sign([ring1, ring2]);
        const tx = mtx.toTX();
        assert(tx.verify(mtx.view));
        const actualSize = tx.getVirtualSize();

        assert(estSize >= actualSize);
      });

      it(`P2WPKH ${ins}-in 1-out`, async () => {
        const ring = KeyRing.generate();
        ring.witness = true;
        const script = ring.getProgram();

        const mtx = new MTX();

        for (let i = 1; i <= ins; i++) {
          const coin = new Coin({
            version: 1,
            height: 1,
            value: 10000,
            script: script,
            coinbase: false,
            hash: Buffer.alloc(32),
            index: 0
          });

          mtx.addCoin(coin);
        }

        mtx.addOutput({
          address: new Address(),
          value: 9000
        });
        const estSize = await mtx.estimateSize();

        mtx.sign(ring);
        const tx = mtx.toTX();
        assert(tx.verify(mtx.view));
        const actualSize = tx.getVirtualSize();

        assert(estSize >= actualSize);
      });

      it(`P2SH 2-of-3 Multisig ${ins}-in 1-out`, async () => {
        const ring1 = KeyRing.generate();
        const ring2 = KeyRing.generate();
        const ring3 = KeyRing.generate();
        const script = Script.fromMultisig(2, 3,
          [
            ring1.publicKey,
            ring2.publicKey,
            ring3.publicKey
          ]);

        const mtx = new MTX();

        for (let i = 1; i <= ins; i++) {
          const coin = new Coin({
            version: 1,
            height: 1,
            value: 10000,
            script: Script.fromScripthash(script.hash160()),
            coinbase: false,
            hash: Buffer.alloc(32),
            index: 0
          });

          mtx.addCoin(coin);
        }

        mtx.addOutput({
          address: new Address(),
          value: 9000
        });
        const estSize = await mtx.estimateSize();

        ring1.script = script;
        ring2.script = script;
        mtx.sign([ring1, ring2]);
        const tx = mtx.toTX();
        assert(tx.verify(mtx.view));
        const actualSize = tx.getVirtualSize();

        assert(estSize >= actualSize);
      });

      it(`P2WSH 2-of-3 Multisig ${ins}-in 1-out`, async () => {
        const ring1 = KeyRing.generate();
        const ring2 = KeyRing.generate();
        const ring3 = KeyRing.generate();
        ring1.witness = true;
        ring2.witness = true;
        ring3.witness = true;
        const script = Script.fromMultisig(2, 3,
          [
            ring1.publicKey,
            ring2.publicKey,
            ring3.publicKey
          ]);

        const mtx = new MTX();

        for (let i = 1; i <= ins; i++) {
          const coin = new Coin({
            version: 1,
            height: 1,
            value: 10000,
            script: Script.fromProgram(0, script.sha256()),
            coinbase: false,
            hash: Buffer.alloc(32),
            index: 0
          });

          mtx.addCoin(coin);
        }

        mtx.addOutput({
          address: new Address(),
          value: 9000
        });
        const estSize = await mtx.estimateSize();

        ring1.script = script;
        ring2.script = script;
        mtx.sign([ring1, ring2]);
        const tx = mtx.toTX();
        assert(tx.verify(mtx.view));
        const actualSize = tx.getVirtualSize();

        assert(estSize >= actualSize);
      });
    }
  });
});
