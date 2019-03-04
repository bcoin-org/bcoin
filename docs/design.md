# Design

Bcoin is thoroughly event driven. It has a fullnode object, but Bcoin was
specifically designed so the mempool, blockchain, p2p pool, and wallet database
could all be used separately. All the fullnode object does is tie these things
together. It's essentially a huge proxying of events. The general communication
between these things looks something like this:

```
pool -> block event -> chain
pool -> tx event -> mempool
chain -> block event -> mempool/miner
chain -> tx event -> walletdb
chain -> reorg event -> walletdb/mempool/miner
mempool -> tx event -> walletdb/miner
miner -> block event -> chain
walletdb -> tx event -> websocket server
websocket server -> tx event -> websocket client
http client -> tx -> http server -> mempool
```

Not only does the loose coupling make testing easier, it ensures people can
utilize bcoin for many use cases. Learn more about specific events and
event emitters at https://bcoin.io/guides/events.html

## Performance

Non-javscript people reading this may think using JavaScript isn't a wise
decision.

### JavaScript

JavaScript is inherently slow due to how dynamic it is, but modern JITs have
solved this issue using very clever optimization and dynamic recompilation
techniques. v8 in some cases can [rival the speed of C++][v8] if the code is
well-written.

### Concurrency

Bcoin runs in node.js, so the JavaScript code is limited to one thread. We
solve this limitation by spinning up persistent worker processes for
transaction verification (webworkers when in the browser). This ensures the
blockchain and mempool do not block the master process very much. It also means
transaction verification can be parallelized.

Strangely enough, workers are faster in the browser than they are in node since
you are allowed to share memory between threads using the transferable API
(Uint8Arrays can be "transferred" to another thread). In node, you have to pipe
data to another process.

But of course, there is a benefit to having a multi-process architecture: the
worker processes can die on their own without disturbing the master process.

Bcoin uses [secp256k1-node][secp256k1-node] for ECDSA verification, which is a
node.js binding to Pieter Wuille's blazingly fast [libsecp256k1][libsecp256k1]
library.

In the browser, bcoin will use [elliptic][elliptic], the fastest JavaScript
ECDSA implementation. It will obviously never beat C and hand-optimized
assembly, but it's still usable.

### Benefits

The real feature of JavaScript is that your code will run almost anywhere. With
bcoin, we now have a full node that will run on almost any browser, on laptops,
on servers, on smartphones, on most devices you can imagine, even by simply
visiting a webpage.

[v8]: https://www.youtube.com/watch?v=UJPdhx5zTaw
[libsecp256k1]: https://github.com/bitcoin-core/secp256k1
[secp256k1-node]: https://github.com/cryptocoinjs/secp256k1-node
[elliptic]: https://github.com/indutny/elliptic
