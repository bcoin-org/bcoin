/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('./util/assert');
const common = require('./util/common');
const {BloomFilter} = require('bfilter');
const {nonce} = require('../lib/net/common');
const Framer = require('../lib/net/framer');
const packets = require('../lib/net/packets');
const NetAddress = require('../lib/net/netaddress');
const {CompactBlock, TXRequest, TXResponse} = require('../lib/net/bip152');
const InvItem = require('../lib/primitives/invitem');
const Headers = require('../lib/primitives/headers');
const Network = require('../lib/protocol/network');

// Block test vectors
const block300025 = common.readBlock('block300025');

// Merkle block test vectors
const merkle300025 = common.readMerkle('merkle300025');

// Small SegWit block test vector
const block482683 = common.readBlock('block482683');

describe('Net', function() {
  describe('Packets', function() {
    it('version', () => {
      const check = (pkt) => {
        assert.equal(pkt.cmd, 'version');
        assert.equal(pkt.type, packets.types.VERSION);
        assert.equal(pkt.version, 70012);
        assert.equal(pkt.services, 10);
        assert.equal(pkt.time, 1558405603);
        assert.equal(pkt.remote.host, '127.0.0.1');
        assert.equal(pkt.remote.port, 8334);
        assert.equal(pkt.local.host, '127.0.0.1');
        assert.equal(pkt.local.port, 8335);
        assert.bufferEqual(pkt.nonce, Buffer.alloc(8, 0x00));
        assert.equal(pkt.agent, 'bcoin');
        assert.equal(pkt.height, 500000);
        assert.equal(pkt.noRelay, true);
      };

      let pkt = new packets.VersionPacket({
        version: 70012,
        services: 10,
        time: 1558405603,
        remote: {
          host: '127.0.0.1',
          port: 8334
        },
        local: {
          host: '127.0.0.1',
          port: 8335
        },
        nonce: Buffer.alloc(8, 0x00),
        agent: 'bcoin',
        height: 500000,
        noRelay: true
      });

      check(pkt);

      pkt = packets.VersionPacket.fromRaw(pkt.toRaw());

      check(pkt);
    });

    it('verack', () => {
      const check = (pkt) => {
        assert.equal(pkt.cmd, 'verack');
        assert.equal(pkt.type, packets.types.VERACK);
      };

      let pkt = new packets.VerackPacket();
      check(pkt);

      pkt = packets.VerackPacket.fromRaw(pkt.toRaw());
      check(pkt);
    });

    it('ping', () => {
      const check = (pkt, nonce) => {
        assert.equal(pkt.cmd, 'ping');
        assert.equal(pkt.type, packets.types.PING);
        if (nonce)
          assert.bufferEqual(pkt.nonce, Buffer.alloc(8, 0x01));
      };

      let pkt = new packets.PingPacket(Buffer.alloc(8, 0x01));
      check(pkt, true);

      pkt = packets.PingPacket.fromRaw(pkt.toRaw());
      check(pkt, true);

      pkt = new packets.PingPacket();
      check(pkt, false);

      pkt = packets.PingPacket.fromRaw(pkt.toRaw());
      check(pkt, false);
    });

    it('pong', () => {
      const check = (pkt, nonce) => {
        assert.equal(pkt.cmd, 'pong');
        assert.equal(pkt.type, packets.types.PONG);
        if (nonce)
          assert.bufferEqual(pkt.nonce, Buffer.alloc(8, 0x01));
        else {
          assert.bufferEqual(pkt.nonce, Buffer.alloc(8, 0x00));
        }
      };

      let pkt = new packets.PongPacket(Buffer.alloc(8, 0x01));
      check(pkt, true);

      pkt = packets.PongPacket.fromRaw(pkt.toRaw());
      check(pkt, true);

      pkt = new packets.PongPacket();
      check(pkt, false);

      pkt = packets.PongPacket.fromRaw(pkt.toRaw());
      check(pkt, false);
    });

    it('getaddr', () => {
      const check = (pkt) => {
        assert.equal(pkt.cmd, 'getaddr');
        assert.equal(pkt.type, packets.types.GETADDR);
      };

      let pkt = new packets.GetAddrPacket();
      check(pkt);

      pkt = packets.GetAddrPacket.fromRaw(pkt.toRaw());
      check(pkt);
    });

    it('addr', () => {
      const check = (pkt) => {
        assert.equal(pkt.cmd, 'addr');
        assert.equal(pkt.type, packets.types.ADDR);

        let addr = pkt.items[0];
        assert.equal(addr.host, '127.0.0.2');
        assert.equal(addr.port, 8334);
        assert.equal(addr.services, 101);
        assert.equal(addr.time, 1558405603);

        addr = pkt.items[1];
        assert.equal(addr.host, '127.0.0.3');
        assert.equal(addr.port, 8333);
        assert.equal(addr.services, 102);
        assert.equal(addr.time, 1558405602);
      };

      const items = [
        new NetAddress({
          host: '127.0.0.2',
          port: 8334,
          services: 101,
          time: 1558405603
        }),
        new NetAddress({
          host: '127.0.0.3',
          port: 8333,
          services: 102,
          time: 1558405602
        })
      ];

      let pkt = new packets.AddrPacket(items);
      check(pkt);

      pkt = packets.AddrPacket.fromRaw(pkt.toRaw());
      check(pkt);
    });

    it('inv', () => {
      const check = (pkt, many) => {
        assert.equal(pkt.cmd, 'inv');
        assert.equal(pkt.type, packets.types.INV);

        let item = pkt.items[0];
        assert.equal(item.type, 1);
        assert.bufferEqual(item.hash, Buffer.alloc(32, 0x01));

        item = pkt.items[1];
        assert.equal(item.type, 1);
        assert.bufferEqual(item.hash, Buffer.alloc(32, 0x02));

        if (many) {
          for (let i = 2; i < 254; i++) {
            item = pkt.items[i];
            assert.equal(item.type, 1);
            assert.bufferEqual(item.hash, Buffer.alloc(32, 0x03));
          }
        }
      };

      const items = [
        new InvItem(InvItem.types.TX, Buffer.alloc(32, 0x01)),
        new InvItem(InvItem.types.TX, Buffer.alloc(32, 0x02))
      ];

      let pkt = new packets.InvPacket(items);
      check(pkt, false);

      pkt = packets.InvPacket.fromRaw(pkt.toRaw());
      check(pkt, false);

      while (items.length < 254)
        items.push(new InvItem(InvItem.types.TX, Buffer.alloc(32, 0x03)));

      pkt = new packets.InvPacket(items);
      check(pkt, true);

      pkt = packets.InvPacket.fromRaw(pkt.toRaw());
      check(pkt, true);
    });

    it('getdata', () => {
      const check = (pkt) => {
        assert.equal(pkt.cmd, 'getdata');
        assert.equal(pkt.type, packets.types.GETDATA);

        let item = pkt.items[0];
        assert.equal(item.type, 1);
        assert.bufferEqual(item.hash, Buffer.alloc(32, 0x01));

        item = pkt.items[1];
        assert.equal(item.type, 1);
        assert.bufferEqual(item.hash, Buffer.alloc(32, 0x02));
      };

      const items = [
        new InvItem(InvItem.types.TX, Buffer.alloc(32, 0x01)),
        new InvItem(InvItem.types.TX, Buffer.alloc(32, 0x02))
      ];

      let pkt = new packets.GetDataPacket(items);
      check(pkt);

      pkt = packets.GetDataPacket.fromRaw(pkt.toRaw());
      check(pkt);
    });

    it('notfound', () => {
      const check = (pkt) => {
        assert.equal(pkt.cmd, 'notfound');
        assert.equal(pkt.type, packets.types.NOTFOUND);

        let item = pkt.items[0];
        assert.equal(item.type, 1);
        assert.bufferEqual(item.hash, Buffer.alloc(32, 0x01));

        item = pkt.items[1];
        assert.equal(item.type, 1);
        assert.bufferEqual(item.hash, Buffer.alloc(32, 0x02));
      };

      const items = [
        new InvItem(InvItem.types.TX, Buffer.alloc(32, 0x01)),
        new InvItem(InvItem.types.TX, Buffer.alloc(32, 0x02))
      ];

      let pkt = new packets.NotFoundPacket(items);
      check(pkt);

      pkt = packets.NotFoundPacket.fromRaw(pkt.toRaw());
      check(pkt);
    });

    it('getblocks', () => {
      const check = (pkt, values) => {
        assert.equal(pkt.cmd, 'getblocks');
        assert.equal(pkt.type, packets.types.GETBLOCKS);

        if (values) {
          assert.equal(pkt.locator.length, 2);
          assert.bufferEqual(pkt.locator[0], Buffer.alloc(32, 0x01));
          assert.bufferEqual(pkt.locator[1], Buffer.alloc(32, 0x02));
          assert.bufferEqual(pkt.stop, Buffer.alloc(32, 0x03));
        } else {
          assert.equal(pkt.locator.length, 0);
          assert.strictEqual(pkt.stop, null);
        }
      };

      const locator = [
        Buffer.alloc(32, 0x01),
        Buffer.alloc(32, 0x02)
      ];

      const stop = Buffer.alloc(32, 0x03);

      let pkt = new packets.GetBlocksPacket(locator, stop);
      check(pkt, true);

      pkt = packets.GetBlocksPacket.fromRaw(pkt.toRaw());
      check(pkt, true);

      pkt = new packets.GetBlocksPacket();
      check(pkt, false);

      pkt = packets.GetBlocksPacket.fromRaw(pkt.toRaw());
      check(pkt, false);
    });

    it('getheaders', () => {
      const check = (pkt, values) => {
        assert.equal(pkt.cmd, 'getheaders');
        assert.equal(pkt.type, packets.types.GETHEADERS);

        if (values) {
          assert.equal(pkt.locator.length, 2);
          assert.bufferEqual(pkt.locator[0], Buffer.alloc(32, 0x01));
          assert.bufferEqual(pkt.locator[1], Buffer.alloc(32, 0x02));
          assert.bufferEqual(pkt.stop, Buffer.alloc(32, 0x03));
        } else {
          assert.equal(pkt.locator.length, 0);
          assert.strictEqual(pkt.stop, null);
        }
      };

      const locator = [
        Buffer.alloc(32, 0x01),
        Buffer.alloc(32, 0x02)
      ];

      const stop = Buffer.alloc(32, 0x03);

      let pkt = new packets.GetHeadersPacket(locator, stop);
      check(pkt, true);

      pkt = packets.GetHeadersPacket.fromRaw(pkt.toRaw());
      check(pkt, true);

      pkt = new packets.GetHeadersPacket();
      check(pkt, false);

      pkt = packets.GetHeadersPacket.fromRaw(pkt.toRaw());
      check(pkt, false);
    });

    it('headers', () => {
      const check = (pkt, values, many) => {
        assert.equal(pkt.cmd, 'headers');
        assert.equal(pkt.type, packets.types.HEADERS);

        assert.equal(pkt.items[0].version, 1);
        assert.bufferEqual(pkt.items[0].prevBlock, Buffer.alloc(32, 0x01));
        assert.bufferEqual(pkt.items[0].merkleRoot, Buffer.alloc(32, 0x02));
        assert.equal(pkt.items[0].time, 1558405603);
        assert.equal(pkt.items[0].bits, 403014710);
        assert.equal(pkt.items[0].nonce, 101);

        assert.equal(pkt.items[1].version, 2);
        assert.bufferEqual(pkt.items[1].prevBlock, Buffer.alloc(32, 0x02));
        assert.bufferEqual(pkt.items[1].merkleRoot, Buffer.alloc(32, 0x03));
        assert.equal(pkt.items[1].time, 1558405604);
        assert.equal(pkt.items[1].bits, 403014711);
        assert.equal(pkt.items[1].nonce, 102);

        if (many) {
          for (let i = 2; i < 254; i++) {
            const item = pkt.items[i];
            assert.equal(item.version, 3);
            assert.bufferEqual(pkt.items[1].prevBlock, Buffer.alloc(32, 0x04));
            assert.bufferEqual(pkt.items[1].merkleRoot, Buffer.alloc(32, 0x05));
            assert.equal(pkt.items[1].time, 1558405605);
            assert.equal(pkt.items[1].bits, 403014712);
            assert.equal(pkt.items[1].nonce, 103);
          }
        }
      };

      const items = [
        new Headers({
          version: 1,
          prevBlock: Buffer.alloc(32, 0x01),
          merkleRoot: Buffer.alloc(32, 0x02),
          time: 1558405603,
          bits: 403014710,
          nonce: 101
        }),
        new Headers({
          version: 2,
          prevBlock: Buffer.alloc(32, 0x02),
          merkleRoot: Buffer.alloc(32, 0x03),
          time: 1558405604,
          bits: 403014711,
          nonce: 102
        })
      ];

      let pkt = new packets.HeadersPacket(items);
      check(pkt, false);

      pkt = packets.HeadersPacket.fromRaw(pkt.toRaw());
      check(pkt, false);

      while (items.length < 254) {
        items.push(new Headers({
          version: 3,
          prevBlock: Buffer.alloc(32, 0x04),
          merkleRoot: Buffer.alloc(32, 0x05),
          time: 1558405605,
          bits: 403014712,
          nonce: 103
        }));
      }

      pkt = new packets.HeadersPacket(items);
      check(pkt, true);

      pkt = packets.HeadersPacket.fromRaw(pkt.toRaw());
      check(pkt, true);
    });

    it('sendheaders', () => {
      const check = (pkt) => {
        assert.equal(pkt.cmd, 'sendheaders');
        assert.equal(pkt.type, packets.types.SENDHEADERS);
      };

      let pkt = new packets.SendHeadersPacket();
      check(pkt);

      pkt = packets.SendHeadersPacket.fromRaw(pkt.toRaw());
      check(pkt);
    });

    it('block', () => {
      const [block] = block300025.getBlock();
      const [witnessBlock] = block482683.getBlock();

      const check = (pkt, witness, read) => {
        assert.equal(pkt.cmd, 'block');
        assert.equal(pkt.type, packets.types.BLOCK);

        if (witness) {
          assert.bufferEqual(pkt.block.hash(), witnessBlock.hash());
          if (!read)
            assert.equal(pkt.witness, true);
        } else {
          assert.bufferEqual(pkt.block.hash(), block.hash());
          assert.equal(pkt.witness, false);
        }
      };

      let pkt = new packets.BlockPacket(block, false);
      check(pkt, false);

      pkt = packets.BlockPacket.fromRaw(pkt.toRaw());
      check(pkt, false);

      pkt = new packets.BlockPacket(witnessBlock, true);
      check(pkt, true);

      pkt = packets.BlockPacket.fromRaw(pkt.toRaw());
      check(pkt, true, true);
    });

    it('tx', () => {
      const [block] = block482683.getBlock();

      const tx = block.txs[9];
      const witnessTx = block.txs[10];

      const check = (pkt, witness, read) => {
        assert.equal(pkt.cmd, 'tx');
        assert.equal(pkt.type, packets.types.TX);

        if (witness) {
          assert.bufferEqual(pkt.tx.hash(), witnessTx.hash());
          if (!read)
            assert.equal(pkt.witness, true);
        } else {
          assert.bufferEqual(pkt.tx.hash(), tx.hash());
          assert.equal(pkt.witness, false);
        }
      };

      let pkt = new packets.TXPacket(tx, false);
      check(pkt, false);

      pkt = packets.TXPacket.fromRaw(pkt.toRaw());
      check(pkt, false);

      pkt = new packets.TXPacket(witnessTx, true);
      check(pkt, true);

      pkt = packets.TXPacket.fromRaw(pkt.toRaw());
      check(pkt, true, true);
    });

    it('reject', () => {
      const check = (pkt) => {
        assert.equal(pkt.cmd, 'reject');
        assert.equal(pkt.type, packets.types.REJECT);

        assert.equal(pkt.code, 1);
        assert.equal(pkt.reason, 'test-reason');
        assert.equal(pkt.message, 'block');

        assert.equal(pkt.getCode(), 'malformed');

        assert.bufferEqual(pkt.hash, Buffer.alloc(32, 0x01));
      };

      let pkt = new packets.RejectPacket({
        message: 'block',
        code: 1,
        reason: 'test-reason',
        hash: Buffer.alloc(32, 0x01)
      });

      check(pkt);

      pkt = packets.RejectPacket.fromRaw(pkt.toRaw());
      check(pkt);

      pkt = packets.RejectPacket.fromReason(
        'malformed',
        'test-reason',
        'block',
        Buffer.alloc(32, 0x01)
      );

      check(pkt);

      pkt = packets.RejectPacket.fromRaw(pkt.toRaw());
      check(pkt);
    });

    it('mempool', () => {
      const check = (pkt) => {
        assert.equal(pkt.cmd, 'mempool');
        assert.equal(pkt.type, packets.types.MEMPOOL);
      };

      let pkt = new packets.MempoolPacket();
      check(pkt);

      pkt = packets.MempoolPacket.fromRaw(pkt.toRaw());
    });

    it('filterload', () => {
      const check = (pkt) => {
        assert.equal(pkt.cmd, 'filterload');
        assert.equal(pkt.type, packets.types.FILTERLOAD);
        assert.equal(pkt.filter.test(Buffer.alloc(32, 0x01)), true);
      };

      const filter = BloomFilter.fromRate(
        20000, 0.001, BloomFilter.flags.ALL);

      filter.add(Buffer.alloc(32, 0x01));

      let pkt = new packets.FilterLoadPacket(filter);
      check(pkt);

      pkt = packets.FilterLoadPacket.fromRaw(pkt.toRaw());
      check(pkt);
    });

    it('filteradd', () => {
      const check = (pkt) => {
        assert.equal(pkt.cmd, 'filteradd');
        assert.equal(pkt.type, packets.types.FILTERADD);
        assert.bufferEqual(pkt.data, Buffer.alloc(32, 0x02));
      };

      let pkt = new packets.FilterAddPacket(Buffer.alloc(32, 0x02));
      check(pkt);

      pkt = packets.FilterAddPacket.fromRaw(pkt.toRaw());
      check(pkt);
    });

    it('filterclear', () => {
      const check = (pkt) => {
        assert.equal(pkt.cmd, 'filterclear');
        assert.equal(pkt.type, packets.types.FILTERCLEAR);
      };

      let pkt = new packets.FilterClearPacket();
      check(pkt);

      pkt = packets.FilterClearPacket.fromRaw(pkt.toRaw());
      check(pkt);
    });

    it('merkleblock', () => {
      const [block] = merkle300025.getBlock();

      const check = (pkt) => {
        assert.equal(pkt.cmd, 'merkleblock');
        assert.equal(pkt.type, packets.types.MERKLEBLOCK);

        assert.bufferEqual(pkt.block.hash(), block.hash());
      };

      let pkt = new packets.MerkleBlockPacket(block);
      check(pkt);

      pkt = packets.MerkleBlockPacket.fromRaw(pkt.toRaw());
      check(pkt);
    });

    it('feefilter', () => {
      const check = (pkt) => {
        assert.equal(pkt.cmd, 'feefilter');
        assert.equal(pkt.type, packets.types.FEEFILTER);

        assert.equal(pkt.rate, 120000);
      };

      let pkt = new packets.FeeFilterPacket(120000);
      check(pkt);

      pkt = packets.FeeFilterPacket.fromRaw(pkt.toRaw());
      check(pkt);
    });

    it('sendcmpct', () => {
      const check = (pkt, mode, version) => {
        assert.equal(pkt.cmd, 'sendcmpct');
        assert.equal(pkt.type, packets.types.SENDCMPCT);

        assert.equal(pkt.mode, mode);
        assert.equal(pkt.version, version);
      };

      let pkt = new packets.SendCmpctPacket();
      check(pkt, 0, 1);

      pkt = packets.SendCmpctPacket.fromRaw(pkt.toRaw());
      check(pkt, 0, 1);

      pkt = new packets.SendCmpctPacket(1, 2);
      check(pkt, 1, 2);

      pkt = packets.SendCmpctPacket.fromRaw(pkt.toRaw());
      check(pkt, 1, 2);
    });

    it('cmpctblock', () => {
      const [block] = block300025.getBlock();
      const [witnessBlock] = block482683.getBlock();

      const check = (pkt, witness, read) => {
        assert.equal(pkt.cmd, 'cmpctblock');
        assert.equal(pkt.type, packets.types.CMPCTBLOCK);

        if (witness) {
          assert.bufferEqual(pkt.block.hash(), witnessBlock.hash());
          if (!read)
            assert.equal(pkt.witness, true);
        } else {
          assert.bufferEqual(pkt.block.hash(), block.hash());
          assert.equal(pkt.witness, false);
        }
      };

      const compact = CompactBlock.fromBlock(block);

      let pkt = new packets.CmpctBlockPacket(compact);
      check(pkt, false);

      pkt = packets.CmpctBlockPacket.fromRaw(pkt.toRaw());
      check(pkt, false);

      const witnessCompact = CompactBlock.fromBlock(witnessBlock);

      pkt = new packets.CmpctBlockPacket(witnessCompact, true);
      check(pkt, true);

      pkt = packets.CmpctBlockPacket.fromRaw(pkt.toRaw());
      check(pkt, true, true);
    });

    it('getblocktxn', () => {
      const check = (pkt) => {
        assert.equal(pkt.cmd, 'getblocktxn');
        assert.equal(pkt.type, packets.types.GETBLOCKTXN);

        assert.bufferEqual(pkt.request.hash, Buffer.alloc(32, 0x01));
        assert.deepEqual(pkt.request.indexes, [2, 3, 5, 7, 11]);
      };

      const request = new TXRequest({
        hash: Buffer.alloc(32, 0x01),
        indexes: [2, 3, 5, 7, 11]
      });

      let pkt = new packets.GetBlockTxnPacket(request);
      check(pkt);

      pkt = packets.GetBlockTxnPacket.fromRaw(pkt.toRaw());
      check(pkt);
    });

    it('blocktxn', () => {
      const [block] = block482683.getBlock();

      const tx = block.txs[9];
      const witnessTx = block.txs[10];

      const check = (pkt, witness, read) => {
        assert.equal(pkt.cmd, 'blocktxn');
        assert.equal(pkt.type, packets.types.BLOCKTXN);

        assert.bufferEqual(pkt.response.hash, Buffer.alloc(32, 0x01));
        if (witness) {
          assert.bufferEqual(pkt.response.txs[0].hash(), witnessTx.hash());
          if (!read)
            assert.equal(pkt.witness, true);
        } else {
          assert.bufferEqual(pkt.response.txs[0].hash(), tx.hash());
          assert.equal(pkt.witness, false);
        }
      };

      const response = new TXResponse({
        hash: Buffer.alloc(32, 0x01),
        txs: [tx]
      });

      let pkt = new packets.BlockTxnPacket(response);
      check(pkt, false);

      pkt = packets.BlockTxnPacket.fromRaw(pkt.toRaw());
      check(pkt, false);

      const witnessResponse = new TXResponse({
        hash: Buffer.alloc(32, 0x01),
        txs: [witnessTx]
      });

      pkt = new packets.BlockTxnPacket(witnessResponse, true);
      check(pkt, true);

      pkt = packets.BlockTxnPacket.fromRaw(pkt.toRaw());
      check(pkt, true, true);
    });

    it('unknown', () => {
      const check = (pkt) => {
        assert.equal(pkt.cmd, 'cmd');
        assert.equal(pkt.type, packets.types.UNKNOWN);
      };

      let pkt = new packets.UnknownPacket('cmd', Buffer.alloc(12, 0x01));
      check(pkt);

      pkt = packets.UnknownPacket.fromRaw('cmd', pkt.toRaw());
      check(pkt);
    });
  });

  describe('Framer', function() {
    it('will construct with network (primary)', () => {
      const framer = new Framer();
      assert.strictEqual(framer.network, Network.get('main'));
    });

    it('will construct with network (custom)', () => {
      const framer = new Framer('regtest');
      assert.strictEqual(framer.network, Network.get('regtest'));
    });

    it('throw with long command', () => {
      const framer = new Framer('regtest');
      let err = null;

      try {
        framer.packet('abcdefghijklm', Buffer.alloc(2, 0x00));
      } catch (e) {
        err = e;
      }
      assert(err);
      assert(err.type, 'AssertionError');
    });

    it('will frame payload with header', () => {
      const framer = new Framer('regtest');

      const pkt = framer.packet('cmd', Buffer.alloc(2, 0x00));

      const magic = pkt.slice(0, 4);
      assert.bufferEqual(magic, Buffer.from('fabfb5da', 'hex'));

      const cmd = pkt.slice(4, 16);
      const cmdbuf = Buffer.from('636d64000000000000000000', 'hex');
      assert.bufferEqual(cmd, cmdbuf);

      const length = pkt.slice(16, 20);
      assert.bufferEqual(length, Buffer.from('02000000', 'hex'));

      const checksum = pkt.slice(20, 24);
      assert.bufferEqual(checksum, Buffer.from('407feb4a', 'hex'));

      const payload = pkt.slice(24, 26);
      assert.bufferEqual(payload, Buffer.from('0000', 'hex'));
    });

    it('will frame payload with header (w/ checksum)', () => {
      const framer = new Framer('regtest');

      const payload = Buffer.alloc(2, 0x00);
      const checksum = Buffer.alloc(4, 0x00);

      const pkt = framer.packet('cmd', payload, checksum);

      assert.bufferEqual(pkt.slice(20, 24), Buffer.from('00000000', 'hex'));
    });
  });

  describe('Common', function() {
    it('will give nonce', async () => {
      const n = nonce();
      assert(Buffer.isBuffer(n));
      assert.equal(n.length, 8);
    });
  });
});
