'use strict';

// Usage: $ node ./docs/Examples/connect-local-nodes.js

const bcoin = require("../..").set("regtest");
const NetAddress = bcoin.net.NetAddress;
const Network = bcoin.Network;

async function delay(ms) {
  return new Promise(resolve => {
    setTimeout(resolve, ms);
  });
}

const regtest = Network.get().toString();
const one = new bcoin.FullNode({
  network: regtest,
  httpPort: 48449 // avoid clash of ports
});

const two = new bcoin.FullNode({
  network: regtest,
  port: 48445,
  listen: true
});

(async () => {
  await one.open();
  await two.open();

  await one.connect();
  await two.connect();

  const addr = new NetAddress({
    host: "127.0.0.1",
    port: two.pool.options.port
  });
  const peer = one.pool.createOutbound(addr);
  one.pool.peers.add(peer);

  // allow some time to establish connection
  await delay(4000);

  await two.disconnect();
  await one.disconnect();

  await two.close();
  await one.close();

  console.log("success!");
})();
