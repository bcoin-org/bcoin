'use strict';

const FullNode = require('../lib/node/fullnode');
const Neutrino = require('../lib/node/neutrino');
const MTX = require('../lib/primitives/mtx');
const assert = require('bsert');
const { consensus } = require('../lib/protocol');
const { forValue } = require('./util/common');

const node1 = new FullNode({
    network: 'regtest',
    memory: true,
    listen: true,
    indexFilter: true,
    plugins: [require('../lib/wallet/plugin')],
    bip157: true
});

const node2 = new Neutrino({
    network: 'regtest',
    memory: true,
    port: 10000,
    httpPort: 20000,
    neutrino: true,
    only: '127.0.0.1',
    plugins: [require('../lib/wallet/plugin')],
    env: {
        'BCOIN_WALLET_HTTP_PORT': '12221'
    }
});

const chain = node1.chain;
const miner = node1.miner;
const wdb1 = node1.require('walletdb').wdb;
const wdb2 = node2.require('walletdb').wdb;

let wallet1 = null;
let wallet2 = null;
let cb = null;

async function mineBlock(tx) {
    const job = await miner.createJob();

    if (!tx)
        return await job.mineAsync();

    const spend = new MTX();
    spend.addTX(tx, 0);

    spend.addOutput(await wallet2.receiveAddress(), 25 * 1e8);
    spend.addOutput(await wallet2.changeAddress(), 5 * 1e8);

    spend.setLocktime(chain.height);
    await wallet1.sign(spend);

    job.addTX(spend.toTX(), spend.view);
    job.refresh();

    return await job.mineAsync();
}

describe('wallet-neutrino', function() {
    it('should open chain and miner', async () => {
        miner.mempool = null;
        consensus.COINBASE_MATURITY = 0;
        await node1.open();
        await node2.open();
    });

    it('should open walletdb', async () => {
        wallet1 = await wdb1.create();
        wallet2 = await wdb2.create();
        miner.addresses.length = 0;
        miner.addAddress(await wallet1.receiveAddress());
    });

    it('should mine 10 blocks', async () => {
        let n = 10;
        while (n) {
            const block = await mineBlock(cb);
            cb = block.txs[0];
            await node1.chain.add(block);
            n--;
        }
    });

    it('should connect nodes', async () => {
        await node1.connect();
        await node2.connect();
    });

    it('should start sync chain', async () => {
        node1.startSync();
        node2.startSync();
        await forValue(node2.chain, 'height', node1.chain.height);
    });

    it('should getheaders', async () => {
        assert.equal(node1.chain.height, node2.chain.height);
    });

    it('should getcfheaders', async () => {
        await new Promise(resolve => setTimeout(resolve, 400));
        const headerHeight = await node2.chain.getCFHeaderHeight();
        assert.equal(headerHeight, node2.chain.height);
    });

    it('should getcfilters', async () => {
        await new Promise(resolve => setTimeout(resolve, 400));
        const filterHeight = await node2.chain.getCFilterHeight();
        assert.equal(filterHeight, node2.chain.height);
    });
});
