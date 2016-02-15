var bcoin = require('../lib/bcoin');
var utils = bcoin.utils;
var net = require('net');
var fs = require('fs');

// Test an SPV sync on main net...

// create a Pool
var pool = new bcoin.pool({
    // Number of peers to connect to
    size: 32,
    // Output debug messages
    debug: true,
    // SPV sync using getheaders and filterload
    type: 'spv',
    fullNode: false,
    //Force downloading of blocks from multiple peers
    multiplePeers: true,
    // main or testnet
    network: 'main',
});

// Peer errors: they happen all the time.
pool.on('error', function(err) {
    utils.print('Error: %s', err.message);
});

// When chain has finished loading:
pool.on('load', function() {
    utils.print('--Chain load complete--');
});

// When a new block is added to the chain:
pool.on('block', function(block, peer) {
    // Give a progress report every 500 blocks
    if (pool.chain.height() % 500 === 0)
        utils.print('block=%s, height=%s', block.rhash, pool.chain.height());
});

// Start the getheaders sync
pool.startSync();