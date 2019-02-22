'use strict';

const bcoin = require('../..');
const plugin = bcoin.wallet.plugin;
const network = bcoin.Network.get('regtest');

const node = new bcoin.FullNode({
  network: 'regtest',
  db: 'memory'
});

node.use(plugin);
const wdb = node.plugins.walletdb.wdb;

(async () => {
  await node.open();

  const feeRate = network.minRelay * 10;

  // Initial blocks mined to
  // wallet/account primary/default then evenly disperses
  // all funds to other wallet accounts
  const numInitBlocks = 200;

  const numTxBlocks = 100; // How many blocks to randomly fill with txs
  const numTxPerBlock = 10; // How many txs to try to put in each block

  const maxOutputsPerTx = 4; // Each tx will have a random # of outputs
  const minSend = 50000; // Each tx output will have a random value
  const maxSend = 100000;

  const walletNames = ['Powell', 'Yellen', 'Bernanke', 'Greenspan', 'Volcker',
    'Miller', 'Burns', 'Martin', 'McCabe', 'Eccles'];
  const accountNames = ['hot', 'cold'];
  const wallets = [];

  /*
   * We are going to bend time, and start our blockchain in the past!
   * Even though we generate these blocks all at once, timestamps in each block
   * will be set ten minutes apart.
   */
  let virtualNow = network.now() - 60 * 10 * (numInitBlocks + numTxBlocks + 1);
  const blockInterval = 60 * 10; // ten minutes
  const mineRegtestBlockToPast = async function(coinbaseAddr) {
    const entry = await node.chain.getEntry(node.chain.tip.hash);
    const job = await node.miner.createJob(entry, coinbaseAddr);
    job.attempt.time = virtualNow;
    virtualNow += blockInterval;
    job.refresh();
    const block = await job.mineAsync();
    await node.chain.add(block);
  };

  console.log('Creating wallets and accounts...');
  for (const wName of walletNames) {
    const wwit = Boolean(Math.random() < 0.5);
    const newWallet = await wdb.create({
      id: wName,
      witness: wwit
    });

    wallets.push(newWallet);

    for (const aName of accountNames) {
      const awit = Boolean(Math.random() < 0.5);
      await newWallet.createAccount({
        name: aName,
        witness: awit
      });
    }
  }

  accountNames.push('default');

  console.log('Mining initial blocks...');
  const primary = await wdb.get('primary');
  const minerReceive = await primary.receiveAddress(0);
  for (let i = 0; i < numInitBlocks; i++) {
    await mineRegtestBlockToPast(minerReceive);
  }

  console.log('Air-dropping funds to the people...');
  // Make sure the wallet is caught up to the chain before proceeding
  await wdb.rescan();
  const balance = await primary.getBalance(0);
  const totalBal = balance.unconfirmed;

  // Adjust for coinbase (im)maturity
  const totalAmt =
    totalBal -
    (bcoin.consensus.COINBASE_MATURITY * bcoin.consensus.BASE_REWARD);

  // Spread out all miner rewards up to this point among the new accounts
  const amtPerAcct = Math.floor(
    totalAmt / (walletNames.length * accountNames.length)
  );

  // Create one massive tx that pays out equal amounts to every account
  const outputs = [];
  for (const wallet of wallets) {
    for (const aName of accountNames) {
      const recAddr = await wallet.receiveAddress(aName);
      outputs.push({
        value: amtPerAcct,
        address: recAddr
      });
    }
  }
  await primary.send({
    outputs: outputs,
    rate: feeRate,
    subtractFee: true
  });

  // Confirm airdrop in a block
  console.log('Confirming airdrop...');
  await mineRegtestBlockToPast(minerReceive);

  // Now we start to randomly generate txs between accounts and add to blocks
  console.log('Creating a big mess!...');
  for (let b = 0; b < numTxBlocks; b++) {
    for (let t = 0; t < numTxPerBlock; t++) {
      // Randomly select recipients for this tx
      const outputs = [];
      let outputTotal = 0;
      const numOutputs = Math.floor(Math.random() * maxOutputsPerTx) + 1;
      for (let o = 0; o < numOutputs; o++) {
        const recWallet = wallets[Math.floor(Math.random() * wallets.length)];
        const recAcct =
          accountNames[Math.floor(Math.random() * accountNames.length)];
        const recAddr = await recWallet.receiveAddress(recAcct);
        const value = Math.floor(
          Math.random() * (maxSend - minSend) + minSend / numOutputs
        );
        outputTotal += value;
        outputs.push({
          value: value,
          address: recAddr
        });
      }

      // Randomly choose a sender for this tx
      const sendWallet = wallets[Math.floor(Math.random() * wallets.length)];
      const sendAcct = accountNames[Math.floor(Math.random() * wallets.length)];
      const acctBal = await sendWallet.getBalance(sendAcct);
      if (acctBal.unconfirmed < outputTotal)
        continue;

      // Send!
      await sendWallet.send({
        account: sendAcct,
        outputs: outputs,
        rate: feeRate,
        subtractFee: true
      });
    }

    // Confirm!
    await mineRegtestBlockToPast(minerReceive);
  }

  console.log('All done! Go play.');
})().catch((err) => {
  console.error(err.stack);
  process.exit(1);
});
