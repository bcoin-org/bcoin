# BlockStore

BlockStore `lib/blockstore` is a bcoin module intended to be used as a backend
for storing block and undo coin data.  It includes a backend that uses flat
files for storage.  Its key benefit is performance improvements across the
board in disk I/O, which is the major bottleneck for the initial block sync.

Blocks are stored in wire format directly to the disk, while some additional
metadata is stored in a key-value store, i.e. LevelDB, to help with the data
management. Both the flat files and the metadata db, are exposed through a
unified interace so that the users can simply read and write blocks without
having to worry about managing data layout on the disk.

In addition to blocks, undo coin data, which is used to revert the changes
applied by a block (in case of a re-org), is also stored on disk, in a similar
fashion.

## Interface

The `AbstractBlockStore` interface defines the following abstract methods to be
defined by concrete implementations:

### Basic housekeeping

* `ensure()`
* `open()`
* `close()`

### Block I/O

* `read(hash, offset, size)`
* `write(hash, data)`
* `prune(hash)`
* `has(hash)`

### Undo Coins I/O

* `readUndo(hash)`
* `writeUndo(hash, data)`
* `pruneUndo(hash)`
* `hasUndo(hash)`

The interface is implemented by `FileBlockStore` and  `LevelBlockStore`, backed
by flat files and LevelDB respectively. We  will focus here on the
`FileBlockStore`, which is the backend that implements a flat file based
storage.

## FileBlockStore

`FileBlockStore` implements the flat file backend for `AbstractBlockStore`.  As
the name suggests, it uses flat files for block/undo data and LevelDB for
metadata.

Let's create a file blockstore, write a block and walk-through the disk storage:

```js
// nodejs
const store = blockstore.create({
  network: 'regtest',
  prefix: '/tmp/blockstore'
});
await store.ensure();
await store.open();
await store.write(hash, block);
```

```sh
// shell
tree /tmp/blockstore/
/tmp/blockstore/
└── blocks
    ├── blk00000.dat
    └── index
        ├── LOG
        ...
```

As we can see, the store writes to the file `blk00000.dat` in
`/tmp/blockstore/blocks/`, and the metadata is written to
`/tmp/blockstore/index`.

Raw blocks are written to the disk in flat files named `blkXXXXX.dat`, where
`XXXXX` is the number of file being currently written, starting at
`blk00000.dat`.  We store the file number as an integer in the metadata db,
expanding the digits to five places.

The metadata db key `layout.F` tracks the last file used for writing.  Each
file in turn tracks the number of blocks in it, the number of bytes used and
its max length.  This data is stored in the db key `layout.f`.

    f['block'][0] => [1, 5, 128]  // blk00000.dat: 1 block written, 5 bytes used, 128 bytes length
    F['block'] => 0   // writing to file blk00000.dat

Each raw block data is preceded by a magic marker defined as follows, to help
identify data written by us:

    magic (8 bytes) = network.magic (4 bytes) + block data length (4 bytes)

For raw undo block data, the hash of the block is also included:

    magic (40 bytes) = network.magic (4 bytes) + length (4 bytes) + hash (32 bytes)

But a marker alone is not sufficient to track the data we write to the files.
For each block we write, we need to store a pointer to the position in the file
where to start reading, and the size of the data we need to seek. This data is
stored in the metadata db using the key `layout.b`:

    b['block']['hash'] => [0, 8, 285] // 'hash' points to file blk00000.dat, position 8, size 285

Using this we know that our block is in `blk00000.dat`, bytes 8 through 293 and its size
is 285 bytes.

Note that the position indicates that the block data is preceded by 8 bytes of
the magic marker.


Examples:

> `store.write('hash', 'block')`

    blk00000:
        0xfabfb5da05000000 block

    index:
        b['block']['hash'] => [0, 8, 5]
        f['block'][0] => [1, 13, 128]
        F['block'] => 0

> `store.write('hash1', 'block1')`

    blk00000:
        0xfabfb5da05000000 block 0xfabfb5da06000000 block1

    index:
        b['block']['hash'] => [0, 8, 5]
        b['block']['hash1'] => [0, 13, 6]
        f['block'][0] => [2, 19, 128]
        F['block'] => 0

> `store.prune('hash1', 'block1')`

    blk00000:
        0xfabfb5da05000000 block 0xfabfb5da06000000 block1

    index:
        b['block']['hash'] => [0, 8, 5]
        f['block'][0] => [1, 19, 128]
        F['block'] => 0
