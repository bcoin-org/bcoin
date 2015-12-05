var bcoin = exports;
var elliptic = require('elliptic');

bcoin.ecdsa = elliptic.ec('secp256k1');
bcoin.utils = require('./bcoin/utils');
bcoin.bloom = require('./bcoin/bloom');
bcoin.protocol = require('./bcoin/protocol');
bcoin.script = require('./bcoin/script');
bcoin.tx = require('./bcoin/tx');
bcoin.txPool = require('./bcoin/tx-pool');
bcoin.block = require('./bcoin/block');
bcoin.chain = require('./bcoin/chain');
bcoin.wallet = require('./bcoin/wallet');
bcoin.peer = require('./bcoin/peer');
bcoin.pool = require('./bcoin/pool');
bcoin.hd = require('./bcoin/hd');
