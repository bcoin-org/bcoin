# bstring

String encodings for javascript.

## Usage

``` js
'use strict';

const assert = require('assert');
const {base58, bech32, cashaddr} = require('bstring');

// Base58
const b58 = base58.encode(Buffer.from([1,2,3]));
assert(base58.test(b58));
const data = base58.decode(b58);
console.log(data);

// Bech32
const b32 = bech32.encode('bc', 0, Buffer.alloc(20, 0x10));
assert(bech32.test(b32));
const {hrp, version, hash} = bech32.decode(b32);
console.log([hrp, version, hash]);

// CashAddr
const address = cashaddr.encode('bitcoincash', 0, Buffer.alloc(20, 0x10));
assert(cashaddr.test(address));
const res1 = cashaddr.decode(address);
console.log([res1.prefix, res1.type, res1.hash]);

const noPrefixAddress = address.split(':')[1];
assert(cashaddr.test(noPrefixAddress, 'bitcoincash'));
const res2 = cashaddr.decode(noPrefixAddress, 'bitcoincash');
console.log([res2.prefix, res2.type, res2.hash]);
```

## Contribution and License Agreement

If you contribute code to this project, you are implicitly allowing your code
to be distributed under the MIT license. You are also implicitly verifying that
all code is your original work. `</legalese>`

## License

- Copyright (c) 2017, Christopher Jeffrey (MIT License).

See LICENSE for more info.
