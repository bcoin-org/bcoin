'use strict';

const express = require('express');
const NodeClient = require('../../../lib/client/node');
const Network = require('../../../lib/protocol/network');
const network = Network.get('regtest');

const WalletClient = require('../../../lib/client/wallet');
const KeyRing = require('../../../lib/primitives/keyring');
const WalletDB = require('../../../lib/wallet/walletdb');





const clientOptions = {
  network: network.type,
  port: 8332,
  apiKey: 'bikeshed'
}
const client = new NodeClient(clientOptions);
const walletOptions = {
  network: network.type,
  port: 48334,
  apiKey: 'bikeshed'
}

const walletClient = new WalletClient(walletOptions);

async function getReceiveAddress(pub) {
  const wdb = new WalletDB({ network: 'regtest' });
  await wdb.open();
  const walletdb = await wdb.create({
    watchOnly: true,
    accountKey: pub,
    witness: false
  });
  const account = await walletdb.getAccount(0);
  const recAddr = account.toJSON().receiveAddress;
  await wdb.close();
  return recAddr;
}


class Router {
  /**
   * Api Router
   * @param {object} options
   * @param {import('express').Express} options.app
   */
  constructor(options) {
    this.app = options.app;
    this.options = options;

  }

  init() {
    this.app.get('/', (req, res, next) => res.send('ο(=•ω＜=)ρ⌒☆'));


    this.app
      .get('/api/v2/tx/:tx', this.getTx)
      .get('/block', this.getBlockByHeight)
      .get('/balance', this.getBalance)
      .get('/api/v2/utxo/:xpubkey', this.getUTXO)
      .get('/tx/address/:address', this.getTxByAddress)
      .get('/api/v2/xpub/:xpubkey', this.getTxs)
      .get('/api/v1/estimatefee/:blocks', this.getEstimateFee)
      .get('/api/v2/sendtx/:txHex',this.sendTX)
  }



  async sendTX(req, res) {
    try {
      const tx = req.params.txHex;
     // const result = await client.broadcast(tx);
     const result = await client.execute('sendrawtransaction', [ tx ]);
      console.log(result);
      res.status(200).json({
        result: result
      });

    } catch (error) {
      console.log('getEstimateFee failed: %o', error);
      res.status(500).json({ error: error.message || error });
    }
  }


  async getEstimateFee(req, res) {
    try {
      const blocks = Number(req.params.blocks);
      console.log(blocks/10);
      const data = await client.estimateFee(blocks/10);
      console.log(data);
      res.status(200).json({
        result: String(data.rate)
      });

    } catch (error) {
      console.log('getEstimateFee failed: %o', error);
      res.status(500).json({ error: error.message || error });
    }
  }



  async getTxs(req, res) {
    try {
      const xpubkey = req.params.xpubkey;
      const address = await getReceiveAddress(xpubkey);
      const txs = await client.getTXByAddress(address);
      const txs_processed = txs.map((item) => {

        let valueIn = 0;
        const vin = item.inputs.map((item) => {
          valueIn += item.coin.value;
          return {
            addresses: [item.coin.address],
            value: item.coin.value,
            coinbase: item.coin.coinbase
          }
        });

        const vout = item.outputs.map((item) => {
          return {
            addresses: [item.address],
            value: item.value
          }
        })

        return {
          txid: item.txid,
          blockTime: item.blockTime,
          blockHeight: item.blockHeight,
          vin: vin,
          vout: vout,
          valueIn: valueIn

        }

      })
      res.status(200).json({
        tokens: [],
        transactions: txs_processed
      });

    } catch (error) {
      console.log('GetTxs failed: %o', error);
      res.status(500).json({ error: error.message || error });
    }
  }


  async getTxByAddress(req, res) {
    const address = req.params.address;
    const result = await client.getTXByAddress(address);
    console.log(result);
    res.status(200).json(result);
  }



  async getUTXO(req, res) {
    try {
      const xpubkey = req.params.xpubkey;
      const clientinfo = await client.getInfo();
      await walletClient.rescan(clientinfo.chain.height);
      try {
        const createWallet = await walletClient.createWallet(xpubkey.slice(0, 40), {
          witness: false,
          watchOnly: true,
          accountKey: xpubkey
        });
        console.log(createWallet);
      } catch (err) {
        console.log(err);
        // console.log('钱包已经存在');
      }


      const wallet = walletClient.wallet(xpubkey.slice(0, 40));
      console.log(await wallet.getAccount('default'));
      const coins = await wallet.getCoins();
      console.log(coins);
      const items = [];
      for (let i of coins) {
        items.push({ value: i.value, 
                    confirmations: i.height > 0 ? 1 : 0 ,
                    address : i.address,
                    height : i.height,
                    path: `m/44'/0'/0'/0/0`,
                    txid: i.hash,
                    vout: i.index
                  })
      }

      res.status(200).json(items);

    } catch (error) {
      console.log('GetUTXO failed: %o', error);
      res.status(500).json({ error: error.message || error });
    }


  }




  async getTx(req, res) {
    try {
      const txid = req.params.tx;
      const data = await client.getTX(txid);



      let valueIn = 0;
      const vin = data.inputs.map((item) => {
        valueIn += item.coin.value;
        return {
          addresses: [item.coin.address],
          value: item.coin.value,
          coinbase: item.coin.coinbase
        }
      });

      const vout = data.outputs.map((item) => {
        return {
          addresses: [item.address],
          value: item.value
        }
      })


      const result = {
        txid: data.hash,
        blockHeight: data.height,
        fees: data.fee,
        blockTime: data.time,
        confirmations: data.confirmations,
        value: 0,
        valueIn: valueIn,
        vin: vin,
        vout: vout


      }
      res.status(200).json(result);

    } catch (error) {
      console.log('GetTx failed: %o', error);
      res.status(500).json({ error: error.message || error });
    }
  }

  async getBlockByHeight(req, res) {
    try {
      const data = await client.execute('getblockbyheight', [Number(req.query.height), 1, 1]);
      res.status(200).json(data);

    } catch (error) {
      console.log('GetNames Block: %o', error);
      res.status(500).json({ error: error.message || error });
    }
  }


  async getBalance(req, res) {
    try {
      const wallet = walletClient.wallet(req.query.id);
      const data = await wallet.getInfo();
      res.status(200).json(data);

    } catch (error) {
      console.log('GetBalance failed: %o', error);
      res.status(500).json({ error: error.message || error });
    }
  }



}

module.exports = Router;
