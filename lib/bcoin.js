var bcoin = exports;
var elliptic = require('elliptic');

bcoin.ecdsa = elliptic.ecdsa(elliptic.nist.secp256k1);
bcoin.utils = require('./bcoin/utils');
bcoin.protocol = require('./bcoin/protocol');
bcoin.wallet = require('./bcoin/wallet');
