# bdb

Database for bcoin (leveldown backend).

## Usage

``` js
const bdb = require('bdb');
const db = bdb.create('/path/to/my.db');

await db.open();

const myPrefix = bdb.key('r');
const myKey = bdb.key('t', ['hash160', 'uint32']);

const bucket = db.bucket(myPrefix.encode());
const batch = bucket.batch();

const hash = Buffer.alloc(20, 0x11);

// Write `foo` to `rt[1111111111111111111111111111111111111111][00000000]`.
batch.put(myKey.encode(hash, 0), Buffer.from('foo'));

await batch.write();

// Iterate:
// From: `rt[0000000000000000000000000000000000000000][00000000]`
// To: `rt[ffffffffffffffffffffffffffffffffffffffff][ffffffff]`
const iter = bucket.iterator({
  gte: myKey.min(),
  lte: myKey.max(),
  values: true
});

await iter.each((key, value) => {
  // Parse each key.
  const [hash, index] = myKey.decode(key);
  console.log('Hash: %s', hash);
  console.log('Index: %d', index);
  console.log('Value: %s', value.toString());
});

await db.close();
```

## Contribution and License Agreement

If you contribute code to this project, you are implicitly allowing your code
to be distributed under the MIT license. You are also implicitly verifying that
all code is your original work. `</legalese>`

## License

- Copyright (c) 2017, Christopher Jeffrey (MIT License).

Parts of this software are based on leveldown:

- Copyright (c) 2017, Rod Vagg (MIT License).

See LICENSE for more info.
