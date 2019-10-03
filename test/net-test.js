/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('bsert');
const AsyncEmitter = require('bevent');
const EventEmitter = require('events');
const {randomBytes} = require('bcrypto/lib/random');
const BN = require('bcrypto/lib/bn.js');
const test = require('./util/common');
const {BloomFilter} = require('bfilter');
const Logger = require('blgr');
const common = require('../lib/net/common');
const services = common.services;
const Framer = require('../lib/net/framer');
const packets = require('../lib/net/packets');
const NetAddress = require('../lib/net/netaddress');
const {CompactBlock, TXRequest, TXResponse} = require('../lib/net/bip152');
const Peer = require('../lib/net/peer');
const Pool = require('../lib/net/pool');
const InvItem = require('../lib/primitives/invitem');
const Headers = require('../lib/primitives/headers');
const MerkleBlock = require('../lib/primitives/merkleblock');
const ChainEntry = require('../lib/blockchain/chainentry');
const chainCommon = require('../lib/blockchain/common');
const Network = require('../lib/protocol/network');
const {VerifyError} = require('../lib/protocol/errors');
const consensus = require('../lib/protocol/consensus');
const util = require('../lib/utils/util');

// Block test vectors
const block300025 = test.readBlock('block300025');

// Merkle block test vectors
const merkle300025 = test.readMerkle('merkle300025');

// Small SegWit block test vector
const block482683 = test.readBlock('block482683');

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

    it('sendheaders (BIP130)', () => {
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

    it('mempool (BIP35)', () => {
      const check = (pkt) => {
        assert.equal(pkt.cmd, 'mempool');
        assert.equal(pkt.type, packets.types.MEMPOOL);
      };

      let pkt = new packets.MempoolPacket();
      check(pkt);

      pkt = packets.MempoolPacket.fromRaw(pkt.toRaw());
    });

    it('filterload (BIP37)', () => {
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

    it('filteradd (BIP37)', () => {
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

    it('filterclear (BIP37)', () => {
      const check = (pkt) => {
        assert.equal(pkt.cmd, 'filterclear');
        assert.equal(pkt.type, packets.types.FILTERCLEAR);
      };

      let pkt = new packets.FilterClearPacket();
      check(pkt);

      pkt = packets.FilterClearPacket.fromRaw(pkt.toRaw());
      check(pkt);
    });

    it('merkleblock (BIP37)', () => {
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

    it('feefilter (BIP133)', () => {
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

    it('sendcmpct (BIP152)', () => {
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

    it('cmpctblock (BIP152)', () => {
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

    it('getblocktxn (BIP152)', () => {
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

    it('blocktxn (BIP152)', () => {
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

  describe('Peer', function() {
    describe('headersUnconnectedMax', function() {
      it('will return true for max unconnected', () => {
        let max = false;
        const peer = Peer.fromOptions({});

        for (let i = 0; i < 4; i++)
          max = peer.headersUnconnectedMax();

        assert.equal(max, true);
      });

      it('will return false for less than max unconnected', () => {
        let max = false;
        const peer = Peer.fromOptions({});

        for (let i = 0; i < 3; i++)
          max = peer.headersUnconnectedMax();

        assert.equal(max, false);
      });

      it('will reset count', () => {
        const now = Date.now();
        let max = false;
        const peer = Peer.fromOptions({});

        for (let i = 0; i < 3; i++)
          max = peer.headersUnconnectedMax();

        peer.headersUnconnectedLast = now - 60002;

        max = peer.headersUnconnectedMax();

        assert.equal(max, false);
      });

      it('will not reset count', () => {
        const now = Date.now();
        let max = false;
        const peer = Peer.fromOptions({});

        for (let i = 0; i < 3; i++)
          max = peer.headersUnconnectedMax();

        peer.headersUnconnectedLast = now - 59998;

        max = peer.headersUnconnectedMax();

        assert.equal(max, true);
      });
    });

    describe('headersMax', function() {
      it('will return true for max headers', () => {
        const peer = Peer.fromOptions({});
        const max = peer.headersMax(2001);
        assert.equal(max, true);
      });

      it('will return false if headers pending', () => {
        const peer = Peer.fromOptions({});
        peer.headersPending = true;
        const max = peer.headersMax(2000);
        assert.equal(max, false);
      });

      it('will set the headers rate', () => {
        const peer = Peer.fromOptions({});
        peer.headersPending = false;

        function broadcast(seconds, expected) {
          peer.headersLast = Date.now() - (seconds * 1000);
          const max = peer.headersMax(2000);
          assert.equal(max, expected, `Seconds: ${seconds}, Expected: ${expected}`);
        }

        broadcast(60, false);
        broadcast(59, true);
        assert.equal(peer.headersCount, 4000);
      });

      it('will set the headers rate (default value)', () => {
        const peer = Peer.fromOptions({});
        peer.headersPending = false;

        function broadcast(expected) {
          const max = peer.headersMax(7);
          assert.equal(max, expected);
        }

        for (let i = 0; i < 285; i++)
          broadcast(false);

        broadcast(true);
        assert.equal(peer.headersCount, 2002);
      });
    });

    describe('handlePacket', function() {
      it('will throw if destroyed', async () => {
        const peer = Peer.fromOptions({});
        let err = null;

        peer.destroyed = true;

        try {
          await peer.handlePacket();
        } catch(e) {
          err = e;
        }

        assert(err);
        assert(err.message, 'Destroyed peer sent a packet.');
      });

      it('will handle types correctly', async () => {
        const map = new Map();
        map.set(packets.types.VERSION, 'handleVersion');
        map.set(packets.types.VERACK, 'handleVerack');
        map.set(packets.types.PING, 'handlePing');
        map.set(packets.types.PONG, 'handlePong');
        map.set(packets.types.GETADDR, false);
        map.set(packets.types.ADDR, false);
        map.set(packets.types.INV, false);
        map.set(packets.types.GETDATA, false);
        map.set(packets.types.NOTFOUND, false);
        map.set(packets.types.GETBLOCKS, false);
        map.set(packets.types.GETHEADERS, false);
        map.set(packets.types.HEADERS, false);
        map.set(packets.types.SENDHEADERS, 'handleSendHeaders');
        map.set(packets.types.BLOCK, false);
        map.set(packets.types.TX, false);
        map.set(packets.types.REJECT, false);
        map.set(packets.types.MEMPOOL, false);
        map.set(packets.types.FILTERLOAD, 'handleFilterLoad');
        map.set(packets.types.FILTERADD, 'handleFilterAdd');
        map.set(packets.types.FILTERCLEAR, 'handleFilterClear');
        map.set(packets.types.MERKLEBLOCK, false);
        map.set(packets.types.FEEFILTER, 'handleFeeFilter');
        map.set(packets.types.SENDCMPCT, 'handleSendCmpct');
        map.set(packets.types.CMPCTBLOCK, false);
        map.set(packets.types.GETBLOCKTXN, false);
        map.set(packets.types.BLOCKTXN, false);
        map.set(packets.types.UNKNOWN, false);
        map.set(packets.types.INTERNAL, false);
        map.set(packets.types.DATA, false);

        const wrap = (type, handler) => {
          const peer = Peer.fromOptions({});
          const result = {count: 0, peer};

          for (const fn of map.values()) {
            if (fn) {
              peer[fn] = (packet) => {
                assert.equal(fn, handler);
                assert(packet);
                assert.equal(packet.type, type);
                result.count += 1;
              };
            }
          }

          return result;
        };

        for (const [type, handler] of map) {
          const stub = wrap(type, handler);
          const packet = {type};

          await stub.peer.handlePacket(packet);
          if (handler)
            assert.equal(stub.count, 1);
          else
            assert.equal(stub.count, 0);
        }
      });
    });

    describe('handleVersion', function() {
      it('will error if already sent version', async () => {
        const peer = Peer.fromOptions({});
        peer.version = 1000;
        const pkt = new packets.VersionPacket();
        let err = null;

        try {
          await peer.handleVersion(pkt);
        } catch (e) {
          err = e;
        }
        assert(err);
      });

      it('will not connect to self', async () => {
        const peer = Peer.fromOptions({});
        peer.options.hasNonce = () => true;

        const pkt = new packets.VersionPacket();
        let err = null;

        try {
          await peer.handleVersion(pkt);
        } catch (e) {
          err = e;
        }
        assert(err);
        assert.equal(err.message, 'We connected to ourself. Oops.');
      });

      it('will error if below min version', async () => {
        const peer = Peer.fromOptions({});

        const pkt = new packets.VersionPacket({version: 70000});
        let err = null;

        try {
          await peer.handleVersion(pkt);
        } catch (e) {
          err = e;
        }
        assert(err);
        const msg = 'Peer does not support required protocol version.';
        assert.equal(err.message, msg);
      });

      it('will error if w/o network service (outbound)', async () => {
        const peer = Peer.fromOptions({});
        peer.outbound = true;

        const pkt = new packets.VersionPacket({services: 0});

        let err = null;

        try {
          await peer.handleVersion(pkt);
        } catch (e) {
          err = e;
        }
        assert(err);
        const msg = 'Peer does not support network services.';
        assert.equal(err.message, msg);
      });

      it('will error if w/o bloom service (outbound)', async () => {
        const peer = Peer.fromOptions({spv: true});
        peer.outbound = true;

        const pkt = new packets.VersionPacket({
          services: 0 | services.NETWORK
        });

        let err = null;

        try {
          await peer.handleVersion(pkt);
        } catch (e) {
          err = e;
        }
        assert(err);
        const msg = 'Peer does not support BIP37.';
        assert.equal(err.message, msg);
      });

      it('will error if w/o bloom version (outbound)', async () => {
        const peer = Peer.fromOptions({spv: true});
        peer.outbound = true;

        const pkt = new packets.VersionPacket({
          services: 0 | services.NETWORK | services.BLOOM,
          version: common.BLOOM_VERSION - 1
        });

        let err = null;

        try {
          await peer.handleVersion(pkt);
        } catch (e) {
          err = e;
        }
        assert(err);
        const msg = 'Peer does not support BIP37.';
        assert.equal(err.message, msg);
      });

      it('will error if w/o witness service (outbound)', async () => {
        const peer = Peer.fromOptions({});
        peer.outbound = true;

        const pkt = new packets.VersionPacket({
          services: 0 | services.NETWORK
        });

        let err = null;

        try {
          await peer.handleVersion(pkt);
        } catch (e) {
          err = e;
        }
        assert(err);
        const msg = 'Peer does not support segregated witness.';
        assert.equal(err.message, msg);
      });

      it('will send ack (outbound)', async () => {
        const peer = Peer.fromOptions({});
        peer.outbound = true;

        const pkt = new packets.VersionPacket({
          services: 0 | services.NETWORK | services.WITNESS
        });

        let called = false;

        peer.send = (packet) => {
          assert(packet);
          assert.equal(packet.type, packets.types.VERACK);
          called = true;
        };

        await peer.handleVersion(pkt);
        assert(called);
      });

      it('will send ack (outbound=false)', async () => {
        const peer = Peer.fromOptions({});
        peer.outbound = false;

        const pkt = new packets.VersionPacket();

        let called = false;

        peer.send = (packet) => {
          assert(packet);
          assert.equal(packet.type, packets.types.VERACK);
          called = true;
        };

        await peer.handleVersion(pkt);
        assert(called);
      });
    });

    describe('handleVerack', function() {
      it('will set ack', async () => {
        const peer = Peer.fromOptions({});
        assert.equal(peer.ack, false);
        const pkt = new packets.VerackPacket();
        await peer.handleVerack(pkt);
        assert.equal(peer.ack, true);
      });
    });

    describe('handlePing', function() {
      it('will not send pong without nonce', async () => {
        const peer = Peer.fromOptions({});
        const pkt = new packets.PingPacket();

        let called = false;
        peer.send = (packet) => {
          called = true;
        };

        await peer.handlePing(pkt);
        assert.equal(called, false);
      });

      it('will send pong', async () => {
        const peer = Peer.fromOptions({});
        const nonce = common.nonce();
        const pkt = new packets.PingPacket(nonce);

        let called = false;
        peer.send = (packet) => {
          assert(packet);
          assert.equal(packet.type, packets.types.PONG);
          assert.bufferEqual(packet.nonce, nonce);
          called = true;
        };

        await peer.handlePing(pkt);
        assert.equal(called, true);
      });
    });

    describe('handlePong', function() {
      it('will not update last pong w/o challenge', async () => {
        const peer = Peer.fromOptions({});
        peer.challenge = null;
        peer.lastPong = -1;
        peer.minPing = -1;

        const pkt = new packets.PongPacket();
        await peer.handlePong(pkt);

        assert.equal(peer.lastPong, -1);
        assert.equal(peer.minPing, -1);
      });

      it('will not update last pong w/ wrong nonce', async () => {
        const peer = Peer.fromOptions({});
        peer.challenge = common.nonce();
        peer.lastPong = -1;
        peer.minPing = -1;

        const pkt = new packets.PongPacket(common.nonce());
        await peer.handlePong(pkt);

        assert.equal(peer.lastPong, -1);
        assert.equal(peer.minPing, -1);
      });

      it('will update last pong and min ping', async () => {
        const now = Date.now();

        const peer = Peer.fromOptions({});
        const nonce = common.nonce();
        peer.challenge = nonce;
        peer.lastPong = -1;
        peer.minPing = -1;

        const pkt = new packets.PongPacket(nonce);
        await peer.handlePong(pkt);

        assert(peer.lastPong >= now);
        assert(peer.minPing >= now - 1);
      });
    });

    describe('handleSendHeaders (BIP130)', function() {
      it('will set prefer headers', async () => {
        const peer = Peer.fromOptions({});
        const pkt = new packets.SendHeadersPacket();
        await peer.handleSendHeaders(pkt);
        assert.equal(peer.preferHeaders, true);
      });
    });

    describe('handleFilterLoad (BIP37)', function() {
      it('will load spv filter', async () => {
        const peer = Peer.fromOptions({});
        const filter = new BloomFilter();
        const pkt = new packets.FilterLoadPacket(filter);
        peer.handleFilterLoad(pkt);
        assert.strictEqual(peer.spvFilter, filter);
      });

      it('will increase ban if not within constraints', async () => {
        const peer = Peer.fromOptions({});
        const filter = new BloomFilter();
        const pkt = new packets.FilterLoadPacket(filter);

        let called = false;
        peer.increaseBan = (score) => {
          assert.equal(score, 100);
          called = true;
        };

        pkt.isWithinConstraints = () => false;
        await peer.handleFilterLoad(pkt);

        assert.equal(called, true);
        assert.strictEqual(peer.spvFilter, null);
      });
    });

    describe('handleFilterAdd (BIP37)', function() {
      it('will add to spv filter', async () => {
        const peer = Peer.fromOptions({});
        peer.spvFilter = BloomFilter.fromRate(
          20000, 0.001, BloomFilter.flags.ALL);

        const data = Buffer.alloc(32, 0x01);

        const pkt = new packets.FilterAddPacket(data);
        await peer.handleFilterAdd(pkt);

        assert.equal(peer.spvFilter.test(data), true);
        assert.equal(peer.noRelay, false);

        peer.spvFilter = null;

        await peer.handleFilterAdd(pkt);
        assert.equal(peer.spvFilter, null);
      });

      it('will increase ban with max push', async () => {
        const peer = Peer.fromOptions({});
        peer.noRelay = true;
        peer.spvFilter = BloomFilter.fromRate(
          20000, 0.001, BloomFilter.flags.ALL);

        let called = false;
        peer.increaseBan = (score) => {
          assert.equal(score, 100);
          called = true;
        };

        const data = Buffer.alloc(521, 0x01);

        const pkt = new packets.FilterAddPacket(data);
        await peer.handleFilterAdd(pkt);

        assert(called);
        assert.equal(peer.spvFilter.test(data), false);
        assert.equal(peer.noRelay, true);
      });
    });

    describe('handleFilterClear (BIP37)', function() {
      it('will reset spv filter', async () => {
        const peer = Peer.fromOptions({});
        peer.spvFilter = BloomFilter.fromRate(
          20000, 0.001, BloomFilter.flags.ALL);

        const data = Buffer.alloc(32, 0x01);
        peer.spvFilter.add(data);
        assert.equal(peer.spvFilter.test(data), true);

        const pkt = new packets.FilterClearPacket();
        await peer.handleFilterClear(pkt);

        assert.equal(peer.spvFilter.test(data), false);
        assert.equal(peer.noRelay, false);
      });

      it('will clear if not set', async () => {
        const peer = Peer.fromOptions({});
        peer.spvFilter = null;

        const pkt = new packets.FilterClearPacket();
        await peer.handleFilterClear(pkt);

        assert.equal(peer.spvFilter, null);
        assert.equal(peer.noRelay, false);
      });
    });

    describe('handleFeeFilter (BIP133)', function() {
      it('will set fee rate', async () => {
        const peer = Peer.fromOptions({});
        const pkt = new packets.FeeFilterPacket(120000);
        await peer.handleFeeFilter(pkt);
        assert.equal(peer.feeRate, 120000);
      });

      it('will increase ban if > max money or negative', async () => {
        const peer = Peer.fromOptions({});
        let called = 0;

        peer.increaseBan = (score) => {
          assert.equal(score, 100);
          called += 1;
        };

        let pkt = new packets.FeeFilterPacket(consensus.MAX_MONEY + 1);
        await peer.handleFeeFilter(pkt);
        assert.equal(called, 1);

        pkt = new packets.FeeFilterPacket(-100);
        await peer.handleFeeFilter(pkt);
        assert.equal(called, 2);
      });
    });

    describe('handleSendCmpct (BIP152)', function() {
      it('will not set compact mode (already set)', async () => {
        const peer = Peer.fromOptions({});
        const pkt = new packets.SendCmpctPacket(1, 1);
        peer.compactMode = 2;
        await peer.handleSendCmpct(pkt);
        assert.equal(peer.compactMode, 2);
      });

      it('will set low-bandwidth mode (mode=0)', async () => {
        const peer = Peer.fromOptions({});
        const pkt = new packets.SendCmpctPacket(0, 1);
        await peer.handleSendCmpct(pkt);
        assert.equal(peer.compactMode, 0);
      });

      it('will set high-bandwidth mode (mode=1)', async () => {
        const peer = Peer.fromOptions({});
        const pkt = new packets.SendCmpctPacket(1, 1);
        await peer.handleSendCmpct(pkt);
        assert.equal(peer.compactMode, 1);
      });

      it('will not set compact mode (mode=2)', async () => {
        const peer = Peer.fromOptions({});
        const pkt = new packets.SendCmpctPacket(2, 1);
        await peer.handleSendCmpct(pkt);
        assert.equal(peer.compactMode, -1);
        assert.equal(peer.compactWitness, false);
      });

      it('will set witness=false (version=1)', async () => {
        const peer = Peer.fromOptions({});
        const pkt = new packets.SendCmpctPacket(0, 1);
        await peer.handleSendCmpct(pkt);
        assert.equal(peer.compactWitness, false);
      });

      it('will set witness=true (version=2)', async () => {
        const peer = Peer.fromOptions({});
        const pkt = new packets.SendCmpctPacket(0, 2);
        await peer.handleSendCmpct(pkt);
        assert.equal(peer.compactWitness, true);
      });

      it('will not set compact mode (version=3)', async () => {
        const peer = Peer.fromOptions({});
        const pkt = new packets.SendCmpctPacket(0, 3);
        await peer.handleSendCmpct(pkt);
        assert.equal(peer.compactMode, -1);
        assert.equal(peer.compactWitness, false);
      });
    });

    describe('maybeTimeout', function() {
      const now = Date.now;
      afterEach(() => {
        Date.now = now;
      });

      function stubDestroy(peer) {
        const results = {
          message: '',
          destroyed: false
        };

        peer.on('error', (err) => {
          results.message = err.message;
        });

        peer.destroy = () => {
          results.destroyed = true;
        };

        return results;
      }

      function stubTime(peer) {
        peer.lastRecv = 105260018;
        peer.lastSend = 105260018;
        peer.time = 105260018;
      }

      it('stalling IBD with block (time)', () => {
        Date.now = () => 105295845 + 120001;
        const peer = Peer.fromOptions({});
        stubTime(peer);

        peer.syncing = true;
        peer.options.isFull = () => false;
        peer.blockTime = 105295845;
        peer.blockMap.set(Buffer.alloc(32, 0x00), 105300148 + 1);

        const results = stubDestroy(peer);
        peer.maybeTimeout();

        assert(results.destroyed);
        assert(results.message.includes('Peer is stalling (block).'));
      });

      it('not stalling IBD with block (time)', () => {
        Date.now = () => 105295845 + 119999;
        const peer = Peer.fromOptions({});
        stubTime(peer);

        peer.syncing = true;
        peer.options.isFull = () => false;
        peer.blockTime = 105295845;
        peer.blockMap.set(Buffer.alloc(32, 0x00), 105300148 + 1);

        const results = stubDestroy(peer);
        peer.maybeTimeout();

        assert(!results.destroyed);
        assert(!results.message);
      });

      it('stalling with block (time)', () => {
        Date.now = () => 105295845 + 120001;
        const peer = Peer.fromOptions({});
        stubTime(peer);

        peer.syncing = true;
        peer.options.isFull = () => true;
        peer.blockTime = 105295845 + 1;
        peer.blockMap.set(Buffer.alloc(32, 0x00), 105295845);

        const results = stubDestroy(peer);
        peer.maybeTimeout();

        assert(results.destroyed);
        assert(results.message.includes('Peer is stalling (block).'));
      });

      it('not stalling with block (time)', () => {
        Date.now = () => 105295845 + 119999;
        const peer = Peer.fromOptions({});
        stubTime(peer);

        peer.syncing = true;
        peer.options.isFull = () => true;
        peer.blockTime = 105295845 + 1;
        peer.blockMap.set(Buffer.alloc(32, 0x00), 105295845);

        const results = stubDestroy(peer);
        peer.maybeTimeout();

        assert(!results.destroyed);
        assert(!results.message);
      });

      it('stalling with header sync', () => {
        Date.now = () => 105295845 + 1;
        const peer = Peer.fromOptions({});
        stubTime(peer);

        peer.options.isRecent = () => false;
        peer.headersTimeout = 105295845;

        const results = stubDestroy(peer);
        peer.maybeTimeout();

        assert(results.destroyed);
        assert(results.message.includes('Peer is stalling (headers sync).'));
      });

      it('not stalling with header sync (time)', () => {
        Date.now = () => 105295845;
        const peer = Peer.fromOptions({});
        stubTime(peer);

        peer.options.isRecent = () => false;
        peer.headersTimeout = 105295845 + 1;

        const results = stubDestroy(peer);
        peer.maybeTimeout();

        assert(!results.destroyed);
        assert(!results.message);
      });

      it('not stalling with header sync (recent)', () => {
        Date.now = () => 105295845 + 1;
        const peer = Peer.fromOptions({});
        stubTime(peer);

        peer.options.isRecent = () => true;
        peer.headersTimeout = 105295845;

        const results = stubDestroy(peer);
        peer.maybeTimeout();

        assert(!results.destroyed);
        assert(!results.message);
        assert.equal(peer.headersTimeout, -1);
      });
    });
  });

  describe('Pool', function() {
    const network = Network.get('regtest');

    describe('setHeadersTimeout', function() {
      const now = Date.now;
      afterEach(() => {
        Date.now = now;
      });

      it('will set based on most work entry', async () => {
        const now = 1564516403115;
        Date.now = () => now;
        const pool = new Pool({
          logger: Logger.global,
          chain: {network, options: {}, on: () => {}}
        });

        const entry = new ChainEntry();
        entry.time = 1296688602;
        pool.chain.mostWork = () => entry;

        const peer = Peer.fromOptions(pool.options);

        pool.setHeadersTimeout(peer);

        assert(typeof peer.headersTimeout === 'number');
        assert(peer.headersTimeout > now);
        assert.equal(peer.headersTimeout, 1564517749495);
      });
    });

    describe('handleVersion', function() {
      it('will update pool time and nonce data', async () => {
        const network = Network.get('regtest');

        const pool = new Pool({
          logger: Logger.global,
          chain: {network, options: {}, on: () => {}}
        });

        const peer = Peer.fromOptions(pool.options);

        const pkt = new packets.VersionPacket({
          time: util.now(),
          remote: {
            host: '127.0.0.1',
            port: 8334
          },
          local: {
            host: '127.0.0.1',
            port: 8335
          },
          nonce: Buffer.alloc(8, 0x00)
        });

        assert(!pool.network.time.known.has(peer.hostname()));
        const nonce = pool.nonces.alloc(peer.hostname());
        assert(pool.nonces.has(nonce));

        await pool.handleVersion(peer, pkt);

        assert(pool.network.time.known.has(peer.hostname()));
        assert(!pool.nonces.has(nonce));
      });

      it('will update local address score', async () => {
        const network = Network.get('regtest');

        const pool = new Pool({
          logger: Logger.global,
          chain: {network, options: {}, on: () => {}}
        });

        let called = false;

        const local = new NetAddress({
          host: '5.19.5.127',
          port: 8334
        });

        pool.hosts = {
          markLocal: (addr) => {
            assert(addr);
            assert.equal(addr.host, local.host);
            assert.equal(addr.port, local.port);
            called = true;
          }
        };

        const peer = Peer.fromOptions(pool.options);

        // The remote address in this case is the address
        // of the receiver of the message, it is the local.
        const pkt = new packets.VersionPacket({remote: local});

        await pool.handleVersion(peer, pkt);

        assert(called);
      });
    });

    describe('handleAddr', function() {
      it('will add addrs to hosts list', async () => {
        const network = Network.get('regtest');

        const pool = new Pool({
          logger: Logger.global,
          chain: {
            network,
            options: {},
            on: () => {},
            state: {
              hasWitness: () => true
            }
          }
        });

        const peer = Peer.fromOptions(pool.options);

        const items = [
          // Routable and has required services
          new NetAddress({
            host: '5.19.5.127',
            port: 8334,
            services: 0 | services.NETWORK | services.WITNESS,
            time: 1558405603
          }),
          // Routable and missing services
          new NetAddress({
            host: '5.29.139.120',
            port: 8335,
            services: 0 | services.NETWORK,
            time: 1558405603
          }),
          // Not routable
          new NetAddress({
            host: '127.0.0.3',
            port: 8333,
            services: 0 | services.NETWORK | services.WITNESS,
            time: 1558405602
          })
        ];

        const pkt = new packets.AddrPacket(items);

        assert.equal(pool.hosts.totalFresh, 0);

        await pool.handleAddr(peer, pkt);

        assert.equal(pool.hosts.totalFresh, 1);
      });
    });

    describe('handleInv', function() {
      const network = Network.get('regtest');

      it('will ban with too many inv', async () => {
        const pool = new Pool({
          logger: Logger.global,
          chain: {network, options: {}, on: () => {}}
        });

        let handleTXInv = false;
        pool.handleTXInv = () => {
          handleTXInv = true;
        };

        let increaseBan = false;
        const peer = Peer.fromOptions(pool.options);
        peer.increaseBan = (score) => {
          assert.equal(score, 100);
          increaseBan = true;
        };

        const items = [];
        for (let i = 0; i < common.MAX_INV + 1; i++)
          items.push(new InvItem(InvItem.types.TX, Buffer.alloc(32, 0x01)));

        const pkt = new packets.InvPacket(items);

        await pool.handleInv(peer, pkt);

        assert(increaseBan);
        assert(!handleTXInv);
      });

      it('will handle block inventory', async () => {
        const pool = new Pool({
          logger: Logger.global,
          chain: {network, options: {}, on: () => {}}
        });

        const peer = Peer.fromOptions(pool.options);

        let handleBlockInv = false;
        pool.handleBlockInv = (_peer, blocks) => {
          assert.strictEqual(_peer, peer);
          assert.bufferEqual(blocks[0], Buffer.alloc(32, 0x01));
          handleBlockInv = true;;
        };

        const pkt = new packets.InvPacket([
          new InvItem(InvItem.types.BLOCK, Buffer.alloc(32, 0x01))
        ]);

        await pool.handleInv(peer, pkt);

        assert(handleBlockInv);
      });

      it('will handle tx inventory', async () => {
        const pool = new Pool({
          logger: Logger.global,
          chain: {network, options: {}, on: () => {}}
        });

        const peer = Peer.fromOptions(pool.options);

        let handleTXInv = false;
        pool.handleTXInv = (_peer, txs) => {
          assert.strictEqual(_peer, peer);
          assert.bufferEqual(txs[0], Buffer.alloc(32, 0x01));
          handleTXInv = true;;
        };

        const pkt = new packets.InvPacket([
          new InvItem(InvItem.types.TX, Buffer.alloc(32, 0x01))
        ]);

        await pool.handleInv(peer, pkt);

        assert(handleTXInv);
      });
    });

    describe('handleBlockInv', function() {
      it('will ignore if not syncing', async () => {
        const pool = new Pool({
          logger: Logger.global,
          chain: {network, options: {}, on: () => {}}
        });

        const peer = Peer.fromOptions(pool.options);
        pool.syncing = false;
        pool.chain.synced = true;

        const hashes = [
          Buffer.alloc(32, 0x00)
        ];

        let called = false;
        pool.getHeaders = async () => {
          called = true;
        };

        await pool.handleBlockInv(peer, hashes);
        assert(!called);
      });

      it('will ignore if not synced', async () => {
        const pool = new Pool({
          logger: Logger.global,
          chain: {network, options: {}, on: () => {}}
        });

        const peer = Peer.fromOptions(pool.options);
        pool.syncing = true;
        pool.chain.synced = false;

        const hashes = [
          Buffer.alloc(32, 0x00)
        ];

        let called = false;
        pool.getHeaders = async () => {
          called = true;
        };

        await pool.handleBlockInv(peer, hashes);
        assert(!called);
      });

      it('will increase ban if block inv sent', async () => {
        const pool = new Pool({
          logger: Logger.global,
          chain: {network, options: {}, on: () => {}}
        });

        const peer = Peer.fromOptions(pool.options);
        const hashes = [Buffer.alloc(32, 0x00)];

        let called = false;
        peer.increaseBan = async (score) => {
          assert.equal(score, 10);
          called = true;
        };

        await pool.handleBlockInv(peer, hashes);
        assert(called);
      });
    });

    describe('handleGetData', function() {
      const network = Network.get('regtest');

      it('will ban with too many items', async () => {
        const pool = new Pool({
          logger: Logger.global,
          chain: {network, options: {}, on: () => {}}
        });

        let increaseBan = false;
        let destroy = false;
        const peer = Peer.fromOptions(pool.options);
        peer.increaseBan = (score) => {
          assert.equal(score, 100);
          increaseBan = true;
        };
        peer.destroy = () => {
          destroy = true;
        };

        const items = [];
        for (let i = 0; i < common.MAX_INV + 1; i++)
          items.push(new InvItem(InvItem.types.TX, Buffer.alloc(32, 0x01)));

        const pkt = new packets.GetDataPacket(items);

        await pool.handleGetData(peer, pkt);

        assert(increaseBan);
        assert(destroy);
      });

      it('will send tx packets', async () => {
        const [block] = block482683.getBlock();

        const tx = block.txs[10];

        const pool = new Pool({
          logger: Logger.global,
          chain: {network, options: {}, on: () => {}}
        });

        const item = new InvItem(InvItem.types.TX, tx.hash());

        const pkt = new packets.GetDataPacket([item]);
        const peer = Peer.fromOptions(pool.options);

        pool.getItem = (_peer, _item) => {
          assert(_peer, peer);

          if (_item.hash.compare(tx.hash()) === 0)
            return tx;

          return null;
        };

        let called = false;
        peer.send = (packet) => {
          assert.equal(packet.type, packets.types.TX);
          assert.strictEqual(packet.tx, tx);
          called = true;
        };

        await pool.handleGetData(peer, pkt);

        assert(called);
      });

      it('will send tx not found', async () => {
        const pool = new Pool({
          logger: Logger.global,
          chain: {network, options: {}, on: () => {}}
        });

        pool.getItem = () => null;

        const pkt = new packets.GetDataPacket([
          new InvItem(InvItem.types.TX, Buffer.alloc(32, 0x01))
        ]);

        const peer = Peer.fromOptions(pool.options);

        let called = false;
        peer.send = (packet) => {
          assert.equal(packet.type, packets.types.NOTFOUND);
          assert.equal(packet.items[0].type, InvItem.types.TX);
          assert.bufferEqual(packet.items[0].hash, Buffer.alloc(32, 0x01));
          called = true;
        };

        await pool.handleGetData(peer, pkt);

        assert(called);
      });

      it('will send block (witness)', async () => {
        const [block] = block482683.getBlock();

        const pool = new Pool({
          logger: Logger.global,
          chain: {
            network,
            options: {},
            on: () => {},
            state: {
              hasWitness: () => true
            },
            getRawBlock: (hash) => {
              assert.bufferEqual(hash, block.hash());
              return block.toRaw();
            }
          }
        });

        const pkt = new packets.GetDataPacket([
          new InvItem(InvItem.types.WITNESS_BLOCK, block.hash())
        ]);

        const peer = Peer.fromOptions(pool.options);

        let called = false;
        peer.sendRaw = (cmd, body) => {
          assert.equal(cmd, 'block');
          assert.bufferEqual(body, block.toRaw());
          called = true;
        };

        await pool.handleGetData(peer, pkt);

        assert(called);
      });

      it('will send block (non-witness)', async () => {
        const [block] = block482683.getBlock();

        const pool = new Pool({
          logger: Logger.global,
          chain: {
            network,
            options: {},
            on: () => {},
            state: {
              hasWitness: () => true
            },
            getBlock: (hash) => {
              assert.bufferEqual(hash, block.hash());
              return block;
            }
          }
        });

        const pkt = new packets.GetDataPacket([
          new InvItem(InvItem.types.BLOCK, block.hash())
        ]);

        const peer = Peer.fromOptions(pool.options);

        let called = false;
        peer.send = (packet) => {
          assert.equal(packet.type, packets.types.BLOCK);
          assert.strictEqual(packet.block, block);
          assert.equal(packet.witness, false);
          called = true;
        };

        await pool.handleGetData(peer, pkt);

        assert(called);
      });

      it('will send block not found', async () => {
        const pool = new Pool({
          logger: Logger.global,
          chain: {
            network,
            options: {},
            on: () => {},
            state: {
              hasWitness: () => true
            },
            getRawBlock: () => null
          }
        });

        const pkt = new packets.GetDataPacket([
          new InvItem(InvItem.types.WITNESS_BLOCK, Buffer.alloc(32, 0x01))
        ]);

        const peer = Peer.fromOptions(pool.options);

        let called = false;
        peer.send = (packet) => {
          assert.equal(packet.type, packets.types.NOTFOUND);
          assert.equal(packet.items[0].type, InvItem.types.WITNESS_BLOCK);
          assert.bufferEqual(packet.items[0].hash, Buffer.alloc(32, 0x01));
          called = true;
        };

        await pool.handleGetData(peer, pkt);

        assert(called);
      });

      it('will destroy if filtered block (bip37=false)', async () => {
        const pool = new Pool({
          logger: Logger.global,
          chain: {network, options: {}, on: () => {}},
          bip37: false
        });

        const pkt = new packets.GetDataPacket([
          new InvItem(InvItem.types.WITNESS_FILTERED_BLOCK,
                      Buffer.alloc(32, 0x01))
        ]);

        const peer = Peer.fromOptions(pool.options);

        let called = false;
        peer.destroy = () => {
          called = true;
        };

        await pool.handleGetData(peer, pkt);

        assert(called);
      });

      it('will send filtered block and txs', async () => {
        const [block] = block300025.getBlock();

        const pool = new Pool({
          logger: Logger.global,
          chain: {network, options: {}, on: () => {}},
          bip37: true
        });

        const filter = BloomFilter.fromRate(20000, 0.001,
                                            BloomFilter.flags.ALL);
        filter.add(block.txs[10].hash());
        filter.add(block.txs[12].hash());

        const peer = Peer.fromOptions(pool.options);
        peer.spvFilter = filter;

        const item = new InvItem(InvItem.types.WITNESS_FILTERED_BLOCK,
                                 block.hash());

        pool.getItem = (_peer, _item) => {
          assert(_peer, peer);

          if (_item.hash.compare(block.hash()) === 0)
            return block;

          return null;
        };

        const pkt = new packets.GetDataPacket([item]);

        let called = 0;
        peer.send = (packet) => {
          switch (called) {
            case 0:
              assert.equal(packet.type, packets.types.MERKLEBLOCK);
              assert.bufferEqual(packet.block.hash(), block.hash());
              break;
            case 1:
              assert.equal(packet.type, packets.types.TX);
              assert.bufferEqual(packet.tx.hash(), block.txs[10].hash());
              break;
            case 2:
              assert.equal(packet.type, packets.types.TX);
              assert.bufferEqual(packet.tx.hash(), block.txs[12].hash());
              break;
          }

          called += 1;
        };

        await pool.handleGetData(peer, pkt);

        assert.equal(called, 3);
      });

      it('will send filtered block not found', async () => {
        const pool = new Pool({
          logger: Logger.global,
          chain: {network, options: {}, on: () => {}},
          bip37: true
        });

        pool.getItem = () => null;

        const pkt = new packets.GetDataPacket([
          new InvItem(InvItem.types.WITNESS_FILTERED_BLOCK,
                      Buffer.alloc(32, 0x01))
        ]);

        const peer = Peer.fromOptions(pool.options);

        let called = false;
        peer.send = (packet) => {
          assert.equal(packet.type, packets.types.NOTFOUND);
          assert.equal(packet.items[0].type,
                       InvItem.types.WITNESS_FILTERED_BLOCK);
          assert.bufferEqual(packet.items[0].hash, Buffer.alloc(32, 0x01));
          called = true;
        };

        await pool.handleGetData(peer, pkt);

        assert(called);
      });

      it('will send compact block not found', async () => {
        const pool = new Pool({
          logger: Logger.global,
          chain: {
            network,
            options: {},
            on: () => {},
            getHeight: () => 500001,
            tip: {
              height: 500001
            }
          }
        });

        pool.getItem = () => null;

        const pkt = new packets.GetDataPacket([
          new InvItem(InvItem.types.CMPCT_BLOCK, Buffer.alloc(32, 0x01))
        ]);

        const peer = Peer.fromOptions(pool.options);

        let called = false;
        peer.send = (packet) => {
          assert.equal(packet.type, packets.types.NOTFOUND);
          assert.equal(packet.items[0].type, InvItem.types.CMPCT_BLOCK);
          assert.bufferEqual(packet.items[0].hash, Buffer.alloc(32, 0x01));
          called = true;
        };

        await pool.handleGetData(peer, pkt);

        assert(called);
      });

      it('will send compact block', async () => {
        const [block] = block300025.getBlock();

        const pool = new Pool({
          logger: Logger.global,
          chain: {
            network,
            options: {},
            on: () => {},
            getHeight: () => 500001,
            tip: {
              height: 500001
            }
          }
        });

        const item = new InvItem(InvItem.types.CMPCT_BLOCK, block.hash());
        const peer = Peer.fromOptions(pool.options);

        pool.getItem = (_peer, _item) => {
          assert(_peer, peer);

          if (_item.hash.compare(block.hash()) === 0)
            return block;

          return null;
        };

        const pkt = new packets.GetDataPacket([item]);

        let called = false;
        peer.send = (packet) => {
          assert.equal(packet.type, packets.types.CMPCTBLOCK);
          assert.bufferEqual(packet.block.hash(), block.hash());
          called = true;
        };

        await pool.handleGetData(peer, pkt);

        assert(called);
      });
    });

    describe('handleGetHeaders', function() {
      function mockHash(height) {
        const hash = Buffer.alloc(32, 0x00);
        hash.writeUInt32LE(height);
        return hash;
      }

      const network = Network.get('regtest');
      let pool = null;

      before(async () => {
        pool = new Pool({
          logger: Logger.global,
          chain: {
            network,
            options: {},
            on: () => {},
            synced: true,
            findLocator: (locators) => {
              assert.bufferEqual(locators[0], mockHash(0));

              return locators[0];
            },
            getNextHash: (hash) => {
              assert.bufferEqual(hash, mockHash(0));

              return mockHash(1);
            },
            getEntry: (hash) => {
              assert.bufferEqual(hash, mockHash(1));

              return new ChainEntry({
                version: 1,
                hash: mockHash(1),
                prevBlock: mockHash(0),
                merkleRoot: Buffer.alloc(32, 0x00),
                time: 1558629632,
                bits: 486604799,
                nonce: 10,
                height: 1
              });
            },
            getNext: (entry) => {
              const height = entry.height + 1;

              return new ChainEntry({
                version: 1,
                hash: mockHash(height),
                prevBlock: entry.hash,
                merkleRoot: Buffer.alloc(32, 0x00),
                time: 1558629632,
                bits: 486604799,
                nonce: 10,
                height: height
              });
            }
          }
        });
      });

      it('will send max headers from chain', async () => {
        const peer = Peer.fromOptions(pool.options);
        peer.handshake = true;

        const locators = [mockHash(0)];
        const stop = mockHash(7500);

        const pkt = new packets.GetHeadersPacket(locators, stop);

        let called = false;
        peer.send = (packet) => {
          assert.equal(packet.type, packets.types.HEADERS);
          assert.equal(packet.items.length, 2000);
          called = true;
        };

        await pool.handleGetHeaders(peer, pkt);
        assert(called);
      });

      it('will continue until stop point', async () => {
        const peer = Peer.fromOptions(pool.options);
        peer.handshake = true;

        const locators = [mockHash(0)];
        const stop = mockHash(1500);

        const pkt = new packets.GetHeadersPacket(locators, stop);

        let called = false;
        peer.send = (packet) => {
          assert.equal(packet.type, packets.types.HEADERS);
          assert.equal(packet.items.length, 1500);
          assert.bufferEqual(packet.items[0].hash(), mockHash(1));
          assert.bufferEqual(packet.items[1499].hash(), mockHash(1500));
          called = true;
        };

        await pool.handleGetHeaders(peer, pkt);
        assert(called);
      });
    });

    describe('handleHeaders', function() {
      function generateHeaders(count) {
        const items = [];
        let last = Buffer.alloc(32, 0x00);

        for (let i = 0; i < count; i++) {
          const header = new Headers({
            version: 1,
            prevBlock: last,
            merkleRoot: Buffer.alloc(32, 0x00),
            time: Date.now() / 1000 | 0,
            nonce: 1,
            bits: 403014710
          });

          items.push(header);
          last = header.hash();
        }

        return items;
      }

      it('will do nothing with empty headers', async () => {
        const pool = new Pool({
          logger: Logger.global,
          chain: {network, options: {}, on: () => {}}
        });
        const peer = Peer.fromOptions(pool.options);
        peer.handshake = true;
        const pkt = new packets.HeadersPacket([]);

        let called = false;
        pool.addHeader = () => {
          called = true;
        };

        await pool.handleHeaders(peer, pkt);
        assert(!called);
      });

      it('will ban peer with too many headers', async () => {
        const pool = new Pool({
          logger: Logger.global,
          chain: {network, options: {}, on: () => {}}
        });
        const peer = Peer.fromOptions(pool.options);
        peer.handshake = true;
        const headers = generateHeaders(2001);
        const pkt = new packets.HeadersPacket(headers);

        let called = false;
        peer.increaseBan = () => {
          called = true;
        };

        await pool.handleHeaders(peer, pkt);
        assert(called);
      });

      it('will ban with high rate of unrequested headers', async () => {
        const pool = new Pool({
          logger: Logger.global,
          chain: {network, options: {}, on: () => {}}
        });
        const peer = Peer.fromOptions(pool.options);
        peer.handshake = true;
        const headers = generateHeaders(1999);
        const pkt = new packets.HeadersPacket(headers);

        let called = false;
        peer.increaseBan = (score) => {
          assert.equal(score, 100);
          called = true;
        };

        pool.chain.hasHeader = async () => true;
        pool.resolveHeaders = () => {};

        await pool.handleHeaders(peer, pkt);
        await pool.handleHeaders(peer, pkt);
        assert(called);
      });

      it('will ask for missing unconnected headers', async () => {
        const pool = new Pool({
          logger: Logger.global,
          chain: {network, options: {}, on: () => {}}
        });
        const peer = Peer.fromOptions(pool.options);
        peer.handshake = true;
        const headers = generateHeaders(7);
        const pkt = new packets.HeadersPacket(headers);

        const entry = new ChainEntry();
        entry.time = 1296688602;
        pool.chain.mostWork = () => entry;

        const locator = [entry.hash];
        pool.chain.getLocator = async (hash) => {
          assert.bufferEqual(hash, entry.hash);
          return locator;
        };

        pool.chain.hasHeader = async () => false;

        let getHeaders = false;
        peer.sendGetHeaders = async (_locator) => {
          assert.deepEqual(_locator, locator);
          getHeaders = true;
        };

        await pool.handleHeaders(peer, pkt);
        assert(getHeaders);
      });

      it('will ban with high rate of unconnected headers', async () => {
        const pool = new Pool({
          logger: Logger.global,
          chain: {network, options: {}, on: () => {}}
        });
        const peer = Peer.fromOptions(pool.options);
        peer.handshake = true;
        const headers = generateHeaders(7);
        const pkt = new packets.HeadersPacket(headers);

        const entry = new ChainEntry();
        entry.time = 1296688602;
        pool.chain.mostWork = () => entry;

        const locator = [entry.hash];
        pool.chain.getLocator = async (hash) => {
          assert.bufferEqual(hash, entry.hash);
          return locator;
        };

        pool.chain.hasHeader = async () => false;

        let ban = false;
        peer.increaseBan = (score) => {
          assert.equal(score, 20);
          ban = true;
        };

        let getHeaders = false;
        peer.sendGetHeaders = async (_locator) => {
          assert.deepEqual(_locator, locator);
          getHeaders = true;
        };

        for (let i = 0; i < 4; i++)
          await pool.handleHeaders(peer, pkt);

        assert(ban);
        assert(getHeaders);
      });

      it('will destroy peer with invalid prevBlock within items', async () => {
        const pool = new Pool({
          logger: Logger.global,
          chain: {network, options: {}, on: () => {}}
        });
        const peer = Peer.fromOptions(pool.options);
        peer.handshake = true;
        peer.headersMax = () => false;

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

        const pkt = new packets.HeadersPacket(items);

        let called = false;
        peer.destroy = () => {
          called = true;
        };

        await pool.handleHeaders(peer, pkt);
        assert(called);
      });

      it('will add connected headers to chain', async () => {
        const pool = new Pool({
          logger: Logger.global,
          chain: {network, options: {}, on: () => {}}
        });
        const peer = Peer.fromOptions(pool.options);
        peer.handshake = true;

        const header1 = new Headers({
          version: 1,
          prevBlock: Buffer.alloc(32, 0x00),
          merkleRoot: Buffer.alloc(32, 0x00),
          time: 1558405603,
          bits: 403014710,
          nonce: 101
        });

        const header2 = new Headers({
          version: 2,
          prevBlock: header1.hash(),
          merkleRoot: Buffer.alloc(32, 0x00),
          time: 1558405604,
          bits: 403014711,
          nonce: 102
        });

        const items = [header1, header2];
        const pkt = new packets.HeadersPacket(items);

        let addCalled = false;
        let height = 0;

        const entry = new ChainEntry();
        entry.time = 1296688602;
        pool.chain.mostWork = () => entry;

        pool.chain.addHeader = async (header, flags) => {
          if (height === 0)
            assert.equal(header, header1);
          if (height === 1)
            assert.equal(header, header2);

          assert.equal(flags, chainCommon.flags.DEFAULT_FLAGS);
          addCalled = true;
          return {height: height++};
        };

        let resolveCalled = false;
        pool.resolveHeaders = () => {
          resolveCalled = true;
        };

        let moreCalled = false;
        pool.chain.getHeaders = async () => {
          moreCalled = true;
        };

        pool.chain.hasHeader = async (hash) => {
          if (Buffer.alloc(32, 0x00).equals(hash))
            return true;
          return false;
        };

        await pool.handleHeaders(peer, pkt);

        assert(addCalled);
        assert(resolveCalled);
        assert(!moreCalled);
        assert.bufferEqual(peer.bestHash, header2.hash());
        assert.equal(peer.bestHeight, 1);
      });

      it('will not add duplicate headers', async () => {
        const pool = new Pool({
          logger: Logger.global,
          chain: {network, options: {}, on: () => {}}
        });
        const peer = Peer.fromOptions(pool.options);
        peer.handshake = true;

        const items = [
          new Headers({
            version: 1,
            prevBlock: Buffer.alloc(32, 0x00),
            merkleRoot: Buffer.alloc(32, 0x00),
            time: 1558405603,
            bits: 403014710,
            nonce: 101
          })
        ];

        const pkt = new packets.HeadersPacket(items);

        let addCalled = false;
        pool.chain.addHeader = async () => {
          addCalled = true;
        };

        pool.resolveHeaders = () => {};
        pool.chain.hasHeader = async () => true;

        await pool.handleHeaders(peer, pkt);

        assert(!addCalled);
      });

      it('will continue to request headers', async () => {
        const pool = new Pool({
          logger: Logger.global,
          chain: {network, options: {}, on: () => {}}
        });
        const peer = Peer.fromOptions(pool.options);
        peer.handshake = true;

        const items = [];

        function addHeader() {
          items.push(new Headers({
            version: 1,
            prevBlock: items.length ?
              items[items.length - 1].hash() :
              Buffer.alloc(32, 0x00),
            merkleRoot: Buffer.alloc(32, 0x00),
            time: 1558405603,
            bits: 403014710,
            nonce: 101
          }));
        }

        while (items.length < 2000)
          addHeader();

        const pkt = new packets.HeadersPacket(items);

        const entry = ChainEntry.fromBlock(items[1999]);
        pool.chain.getEntryByHash = async (hash) => {
          assert.bufferEqual(hash, entry.hash);
          return entry;
        };

        pool.chain.tip = new ChainEntry();
        pool.chain.tip.chainwork = new BN(1);

        pool.chain.getLocator = async (hash) => {
          assert.bufferEqual(hash, entry.hash);
          return [hash];
        };

        pool.chain.hasHeader = async () => false;
        pool.chain.addHeader = async () => {
          return {height: 0};
        };
        pool.resolveHeaders = () => {};

        let called = false;
        peer.sendGetHeaders = async (locator) => {
          assert.bufferEqual(locator[0], items[items.length - 1].hash());
          called = true;
        };

        await pool.handleHeaders(peer, pkt);
        assert(called);
      });
    });

    describe('calculateDelay', function() {
      it('will calculate zero delay', () => {
        const pool = new Pool({
          logger: Logger.global,
          chain: {network, options: {}, on: () => {}}
        });

        pool.chain.tip = new ChainEntry();
        pool.chain.tip.chainwork = new BN('07fcc714b6231092ce0aa38e', 16);

        const entry = new ChainEntry();
        entry.chainwork = new BN('07fcc714b6231092ce0aa38e', 16);

        const delay = pool.calculateDelay(entry);

        assert.equal(delay, 0);
      });

      it('will calculate small delay', () => {
        const pool = new Pool({
          logger: Logger.global,
          chain: {network, options: {}, on: () => {}}
        });

        pool.chain.tip = new ChainEntry();
        pool.chain.tip.chainwork = new BN('07fcc714b6231092ce0aa38e', 16);

        const entry = new ChainEntry();
        entry.chainwork = new BN('07fc171a7d28670a2753c52d', 16);

        const delay = pool.calculateDelay(entry);

        assert.equal(delay, 183);
      });

      it('will calculate large delay', () => {
        const pool = new Pool({
          logger: Logger.global,
          chain: {network, options: {}, on: () => {}}
        });

        pool.chain.tip = new ChainEntry();
        pool.chain.tip.chainwork = new BN('07fcc714b6231092ce0aa38e', 16);

        const entry = new ChainEntry();
        entry.chainwork = new BN('0100010001', 16);

        const delay = pool.calculateDelay(entry);

        assert.equal(delay, 9999);
      });
    });

    describe('resolveHeaders', function() {
      function stubPeer(pool, options) {
        const peer = {
          hostname: () => options.hostname,
          outbound: options.outbound,
          syncing: options.syncing,
          id: options.id
        };

        pool.peers.add(peer);
      }

      it('will only resolve once at a time w/ deferred', async () => {
        const pool = new Pool({
          logger: Logger.global,
          chain: {network, options: {}, on: () => {}}
        });

        let called = 0;
        pool._resolveHeaders = async () => {
          return new Promise((resolve) => {
            setImmediate(() => {
              called += 1;
              resolve();
            });
          });
        };

        pool.resolveHeaders();
        assert.equal(pool.resolveDeferred, false);

        pool.resolveHeaders();
        assert.equal(pool.resolveDeferred, true);

        await pool.resolvePending;
        assert.equal(called, 1);

        await pool.resolvePending;
        assert.equal(called, 2);

        assert.equal(pool.resolveDeferred, false);
      });

      it('will do nothing if headers are not recent', async () => {
        const pool = new Pool({
          logger: Logger.global,
          chain: {network, options: {}, on: () => {}}
        });

        pool.chain.isRecent = () => false;

        let called = 0;
        pool.resolveHeadersForPeer = () => {
          called += 1;
        };

        stubPeer(pool, {
          id: 0,
          hostname: '127.0.0.1:8333',
          outbound: true,
          syncing: true
        });

        await pool.resolveHeaders();
        assert.equal(called, 0);
      });

      it('will wait for more in-flight blocks', async () => {
        const pool = new Pool({
          logger: Logger.global,
          chain: {network, options: {}, on: () => {}}
        });

        pool.chain.isRecent = () => true;

        let called = 0;
        pool.resolveHeadersForPeer = () => {
          called += 1;
        };

        stubPeer(pool, {
          id: 0,
          hostname: '127.0.0.1:8333',
          outbound: true,
          syncing: true
        });

        for (let i = 0; i < 1024; i++)
          pool.blockMap.set(randomBytes(32), 0);

        await pool.resolveHeaders();
        assert.equal(called, 0);
      });

      it('will resolve headers for each peer', async () => {
        const pool = new Pool({
          logger: Logger.global,
          chain: {network, options: {}, on: () => {}}
        });

        pool.chain.isRecent = () => true;

        let called = 0;
        pool.resolveHeadersForPeer = () => {
          called += 1;
        };

        stubPeer(pool, {
          id: 0,
          hostname: '127.0.0.1:8333',
          outbound: true,
          syncing: true
        });

        stubPeer(pool, {
          id: 1,
          hostname: '127.0.0.2:8333',
          outbound: true,
          syncing: true
        });

        pool.resolveHeaders();
        await pool.resolvePending;

        assert.equal(called, 2);
      });
    });

    describe('resolveHeadersForPeer', function() {
      function stubBase(pool, syncable) {
        pool.isSyncable = () => syncable;
        pool.getNextBlocks = async () => {
          throw new Error('Called.');
        };
      }

      it('will skip if peer is not syncable', async () => {
        const pool = new Pool({
          logger: Logger.global,
          chain: {network, options: {}, on: () => {}}
        });

        stubBase(pool, false);

        const peer = Peer.fromOptions(pool.options);
        peer.bestHash = Buffer.alloc(32, 0x00);

        pool.resolveHeadersForPeer(peer);
      });

      it('will wait for all in-flight blocks to finish', async () => {
        const pool = new Pool({
          logger: Logger.global,
          chain: {network, options: {}, on: () => {}}
        });

        stubBase(pool, true);

        const peer = Peer.fromOptions(pool.options);
        peer.blockMap.set(Buffer.alloc(32, 0x00), Date.now());
        peer.bestHash = Buffer.alloc(32, 0x00);

        pool.resolveHeadersForPeer(peer);
      });

      it('will wait/ask for peer best block header', async () => {
        const pool = new Pool({
          logger: Logger.global,
          chain: {network, options: {}, on: () => {}}
        });

        stubBase(pool, true);

        let called = false;
        pool.sendSync = () => {
          called = true;
        };

        const peer = Peer.fromOptions(pool.options);

        pool.resolveHeadersForPeer(peer);
        assert(called);
      });

      it('will check that the peer best header is verified', async () => {
        const pool = new Pool({
          logger: Logger.global,
          chain: {network, options: {}, on: () => {}}
        });

        stubBase(pool, true);

        let called = false;
        pool.chain.getEntryByHash = async (hash) => {
          assert.bufferEqual(hash, Buffer.alloc(32, 0x01));
          called = true;
          return null;
        };

        const peer = Peer.fromOptions(pool.options);
        peer.bestHash = Buffer.alloc(32, 0x01);

        await pool.resolveHeadersForPeer(peer);
        assert(called);
      });

      it('will not download blocks without chainwork', async () => {
        const pool = new Pool({
          logger: Logger.global,
          chain: {network, options: {}, on: () => {}}
        });

        stubBase(pool, true);

        const entry = new ChainEntry();
        assert(entry.chainwork.eq(new BN(0)));
        pool.chain.getEntryByHash = async () => entry;
        pool.chain.tip = {chainwork: new BN(1)};

        const peer = Peer.fromOptions(pool.options);
        peer.bestHash = Buffer.alloc(32, 0x00);

        await pool.resolveHeadersForPeer(peer);
      });

      it('will find next blocks to download', async () => {
        const pool = new Pool({
          logger: Logger.global,
          chain: {network, options: {}, on: () => {}}
        });

        stubBase(pool, true);

        let called = false;
        pool.getNextBlocks = async (peer, best) => {
          assert(peer);
          assert(best);
          called = true;
        };

        const entry = new ChainEntry();
        entry.chainwork = new BN(101);
        pool.chain.getEntryByHash = async () => entry;
        pool.chain.tip = {chainwork: new BN(100)};

        const peer = Peer.fromOptions(pool.options);
        peer.bestHash = Buffer.alloc(32, 0x00);

        await pool.resolveHeadersForPeer(peer);
        assert(called);
      });
    });

    describe('getNextBlocks', function() {
      function mockHash(height, fork) {
        const hash = Buffer.alloc(32, 0x00);
        if (!fork)
          hash.writeUInt32LE(height);
        else
          hash.writeUInt32BE(height);
        return hash;
      }

      function parseMockHash(hash, fork) {
        if (fork)
          return hash.readUInt32BE();
        else
          return hash.readUInt32LE();
      }

      function mockEntry(height) {
        assert(height > 0);

        return new ChainEntry({
          version: 1,
          hash: mockHash(height),
          prevBlock: mockHash(height - 1),
          merkleRoot: Buffer.alloc(32, 0x00),
          time: 1558629632,
          bits: 486604799,
          nonce: 10,
          height: height
        });
      }

      function stubChainDB(pool) {
        const results = {nextCalls: 0};
        pool.chain.db = {
          getNextPath: async (entry, height, limit) => {
            results.nextCalls += 1;
            results.nextArgs = {entry, height, limit};

            const entries = [];

            while (entries.length < limit)
              entries.push(mockEntry(++height));

            return entries;
          },
          hasInvalid: async () => false
        };

        pool.chain.db.hasBlock = () => false;

        return results;
      }

      function stubChain(pool, fork) {
        const common = mockEntry(1);

        pool.chain.getHash = async () => common.hash;
        pool.chain.getEntryByHash = async () => common;
        pool.chain.commonAncestor = async () => fork ? fork : common;
        pool.chain.isMainChain = async () => false;
        pool.chain.locker = {has: () => false};
      }

      it('will not request blocks', async () => {
        const pool = new Pool({
          logger: Logger.global,
          chain: {network, options: {}, on: () => {}}
        });

        stubChain(pool);

        const peer = Peer.fromOptions(pool.options);
        const best = new ChainEntry();

        let called = false;
        pool.getBlock = () => {
          called = true;
        };

        await pool.getNextBlocks(peer, best);
        assert(!called);
      });

      it('will walk w/ peer limit and in-flight', async () => {
        const pool = new Pool({
          logger: Logger.global,
          chain: {network, options: {}, on: () => {}}
        });

        // Every third block already in-flight.
        for (let i = 0; i < 1024; i++) {
          if (i % 3 === 0)
            pool.blockMap.set(mockHash(i), 0);
        }

        stubChain(pool);

        const results = stubChainDB(pool);

        const peer = Peer.fromOptions(pool.options);
        const best = mockEntry(1024);

        let called = false;
        pool.getBlock = (_peer, items) => {
          assert.equal(_peer, peer);
          assert.equal(items.length, 128);
          called = true;
        };

        await pool.getNextBlocks(peer, best);

        assert(called);
        assert.equal(results.nextCalls, 2);
        assert.equal(results.nextArgs.entry.height, best.height);
        assert.equal(results.nextArgs.height, 129);
        assert.equal(results.nextArgs.limit, 128);
      });

      it('will stay within window (plus one)', async () => {
        const pool = new Pool({
          logger: Logger.global,
          chain: {network, options: {}, on: () => {}}
        });

        // All within window except the last 64 is in-flight.
        for (let i = 1; i <= 1025 - 64; i++)
          pool.blockMap.set(mockHash(i), 0);

        stubChain(pool);

        const results = stubChainDB(pool);

        const peer = Peer.fromOptions(pool.options);
        const best = mockEntry(2048);

        let called = false;
        pool.getBlock = (_peer, items) => {
          assert.equal(_peer, peer);
          assert.equal(items.length, 64);
          called = true;
        };

        const staller = await pool.getNextBlocks(peer, best);

        assert(called);
        assert.equal(results.nextCalls, (1024 / 128) + 1);
        assert.equal(staller, -1);
      });

      it('will identify stalling peer', async () => {
        const pool = new Pool({
          logger: Logger.global,
          chain: {network, options: {}, on: () => {}}
        });

        // All within window are in-flight.
        for (let i = 1; i <= 1025; i++)
          pool.blockMap.set(mockHash(i), i);

        stubChain(pool);

        const results = stubChainDB(pool);

        const peer = Peer.fromOptions(pool.options);
        const best = mockEntry(2048);

        let called = false;
        pool.getBlock = () => {
          called = true;
        };

        const staller = await pool.getNextBlocks(peer, best);

        assert(!called);
        assert.equal(results.nextCalls, (1024 / 128) + 1);
        assert.equal(staller, 2);
      });

      it('will stop with invalid blocks', async () => {
        const pool = new Pool({
          logger: Logger.global,
          chain: {network, options: {}, on: () => {}}
        });

        stubChain(pool);

        const results = stubChainDB(pool);

        let called = false;
        pool.chain.db.hasInvalid = async (hash) => {
          assert.bufferEqual(hash, mockHash(2));
          called = true;
          return true;
        };

        const peer = Peer.fromOptions(pool.options);
        const best = mockEntry(1024);

        await pool.getNextBlocks(peer, best);

        assert(called);
        assert.equal(results.nextCalls, 1);
      });

      it('will update the common hash', async () => {
        const pool = new Pool({
          logger: Logger.global,
          chain: {network, options: {}, on: () => {}}
        });

        const fork = mockEntry(1, true);
        stubChain(pool, fork);
        stubChainDB(pool);

        const peer = Peer.fromOptions(pool.options);
        const best = mockEntry(1024);

        let called = false;
        pool.getBlock = (_peer, items) => {
          assert.equal(_peer, peer);
          assert.equal(items.length, 128);
          called = true;
        };

        await pool.getNextBlocks(peer, best);

        assert.bufferEqual(peer.commonHash, fork.hash);
        assert.equal(peer.commonHeight, fork.height);

        assert(called);
      });

      it('will not request main chain blocks', async () => {
        const pool = new Pool({
          logger: Logger.global,
          chain: {network, options: {}, on: () => {}}
        });

        stubChain(pool);
        pool.chain.isMainChain = () => true;
        stubChainDB(pool);

        const peer = Peer.fromOptions(pool.options);
        const best = mockEntry(1024);

        let called = false;
        pool.getBlock = () => {
          called = true;
        };

        await pool.getNextBlocks(peer, best);

        assert.equal(peer.commonHeight, 1025);
        assert.bufferEqual(peer.commonHash, mockHash(1025));

        assert(!called);
      });

      it('will not request blocks being processed', async () => {
        const pool = new Pool({
          logger: Logger.global,
          chain: {network, options: {}, on: () => {}}
        });

        stubChain(pool);
        pool.chain.locker.has = () => true;
        stubChainDB(pool);

        const peer = Peer.fromOptions(pool.options);
        const best = mockEntry(1024);

        let called = false;
        pool.getBlock = () => {
          called = true;
        };

        await pool.getNextBlocks(peer, best);

        assert(!called);
      });

      it('will connect previously saved blocks', async () => {
        const pool = new Pool({
          logger: Logger.global,
          chain: {network, options: {}, on: () => {}}
        });

        stubChain(pool);
        stubChainDB(pool);
        pool.chain.getPrevious = async (entry) => {
          const height = parseMockHash(entry.hash);
          return mockEntry(height - 1);
        };

        pool.chain.db.hasBlock = (hash) => {
          const height = parseMockHash(hash);
          if (height % 2 === 0)
            return true;

          return false;
        };

        const peer = Peer.fromOptions(pool.options);
        const best = mockEntry(1024);

        let blockCalled = false;
        pool.getBlock = () => {
          blockCalled = true;
        };

        let callCount = 0;
        pool.attachBlock = (entry) => {
          assert.equal(entry.height % 2, 0);
          callCount += 1;
        };

        await pool.getNextBlocks(peer, best);

        assert(blockCalled);
        assert.equal(callCount, 1);
      });
    });

    describe('handleBad', function() {
      it('will be called with "bad block" chain event', async () => {
        const chain = new AsyncEmitter();
        chain.network = network;
        chain.options = {};
        const pool = new Pool({logger: Logger.global, chain});

        const err = new Error('Test.');
        const id = 10;

        let called = false;
        pool.handleBad = (msg, _err, _id) => {
          assert.equal(msg, 'block');
          assert.equal(_err, err);
          assert.equal(_id, id);
          called = true;
        };

        chain.emit('bad block', err, id);
        assert(called);
      });

      it('will be called with "bad orphan" mempool event', async () => {
        const mempool = new EventEmitter();
        const chain = {network, options: {}, on: () => {}};
        const pool = new Pool({logger: Logger.global, chain, mempool});

        const err = new Error('Test.');
        const id = 10;

        let called = false;
        pool.handleBad = (msg, _err, _id) => {
          assert.equal(msg, 'tx');
          assert.equal(_err, err);
          assert.equal(_id, id);
          called = true;
        };

        mempool.emit('bad orphan', err, id);
        assert(called);
      });

      it('will ignore if peer not found', async () => {
        const pool = new Pool({
          logger: Logger.global,
          chain: {network, options: {}, on: () => {}}
        });

        const err = new Error('Test.');
        const id = 10;

        pool.handleBad('block', err, id);
      });

      it('will reject peer based on type and error', async () => {
        const pool = new Pool({
          logger: Logger.global,
          chain: {network, options: {}, on: () => {}}
        });

        const err = new Error('Test.');

        const id = 10;
        const peer = Peer.fromOptions(pool.options);
        peer.id = id;

        let called = false;
        peer.reject = (msg, _err) => {
          assert.equal(msg, 'block');
          assert.equal(_err, err);
          called = true;
        };

        pool.peers.add(peer);
        pool.handleBad('block', err, id);
        assert(called);
      });
    });

    describe('handleTX', function() {
      const [block] = block300025.getBlock();

      const network = Network.get('regtest');

      it('will destroy if unrequested', async () => {
        const pool = new Pool({
          logger: Logger.global,
          chain: {network, options: {}, on: () => {}}
        });

        const peer = Peer.fromOptions(pool.options);

        pool.resolveTX = (_peer, hash) => {
          assert.strictEqual(_peer, peer);
          assert.bufferEqual(hash, block.txs[10].hash());
          return false;
        };

        let called = false;
        peer.destroy = () => {
          called = true;
        };

        const pkt = new packets.TXPacket(block.txs[10]);

        await pool.handleTX(peer, pkt);
        assert(called);
      });

      it('will add tx to mempool', async () => {
        let added = false;

        const pool = new Pool({
          logger: Logger.global,
          chain: {
            network,
            options: {},
            on: () => {}
          }
        });

        const peer = Peer.fromOptions(pool.options);

        pool.resolveTX = () => true;
        pool.mempool = {
          addTX: (tx, id) => {
            assert.strictEqual(tx, block.txs[10]);
            assert.equal(id, peer.id);
            added = true;
            return false;
          },
          on: () => {}
        };

        const pkt = new packets.TXPacket(block.txs[10]);

        await pool.handleTX(peer, pkt);
        assert(added);
      });

      it('will increase ban if invalid', async () => {
        const pool = new Pool({
          logger: Logger.global,
          chain: {
            network,
            options: {},
            on: () => {}
          },
          mempool: {
            addTX: (tx) => {
              throw new VerifyError(tx, 'invalid', 'test-reason', 10);
            },
            on: () => {}
          }
        });

        const peer = Peer.fromOptions(pool.options);

        let increaseBan = false;
        peer.increaseBan = (score) => {
          assert.equal(score, 10);
          increaseBan = true;
        };

        let send = false;
        peer.send = (packet) => {
          assert.equal(packet.type, packets.types.REJECT);
          send = true;
        };

        pool.resolveTX = () => true;

        const pkt = new packets.TXPacket(block.txs[10]);

        await pool.handleTX(peer, pkt);
        assert(increaseBan);
        assert(send);
      });
    });

    describe('handleMerkleBlock/handleTX (BIP37)', function() {
      const network = Network.get('regtest');

      it('will add block w/ merkle block and txs', async () => {
        const [block] = block300025.getBlock();

        const pool = new Pool({
          logger: Logger.global,
          chain: {
            network,
            options: {spv: true},
            on: () => {}
          },
          spv: true
        });
        pool.syncing = true;

        const filter = BloomFilter.fromRate(20000, 0.001,
                                            BloomFilter.flags.ALL);
        filter.add(block.txs[10].hash());
        filter.add(block.txs[12].hash());

        // Serialize the block as the txs are not included
        // over the network, however the txs are included in
        // the data structure.
        const merkle = MerkleBlock.fromRaw(block.toMerkle(filter).toRaw());

        const blkpkt = new packets.MerkleBlockPacket(merkle);
        const tx1pkt = new packets.TXPacket(block.txs[10]);
        const tx2pkt = new packets.TXPacket(block.txs[12]);

        const peer = Peer.fromOptions(pool.options);
        peer.blockMap.set(block.hash(), Date.now());

        let called = false;

        pool._addBlock = (_peer, _block, flags) => {
          assert.strictEqual(_peer, peer);
          assert.bufferEqual(_block.hash(), block.hash());
          assert.equal(_block.txs.length, 2);
          assert.strictEqual(_block.txs[0], block.txs[10]);
          assert.strictEqual(_block.txs[1], block.txs[12]);
          called = true;
        };

        await pool.handleMerkleBlock(peer, blkpkt);
        await pool.handleTX(peer, tx1pkt);
        await pool.handleTX(peer, tx2pkt);

        assert(called);
      });
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
      const n = common.nonce();
      assert(Buffer.isBuffer(n));
      assert.equal(n.length, 8);
    });
  });
});
