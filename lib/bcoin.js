var bcoin = exports;
var elliptic = require('elliptic');

bcoin.ecdsa = elliptic.ecdsa(elliptic.nist.secp256k1);
bcoin.utils = require('./bcoin/utils');
bcoin.bloom = require('./bcoin/bloom');
bcoin.protocol = require('./bcoin/protocol');
bcoin.tx = require('./bcoin/tx');
bcoin.block = require('./bcoin/block');
bcoin.chain = require('./bcoin/chain');
bcoin.wallet = require('./bcoin/wallet');
bcoin.peer = require('./bcoin/peer');
bcoin.pool = require('./bcoin/pool');
