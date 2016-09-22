;(function() {

'use strict';

var utils = bcoin.utils;
var body = document.getElementsByTagName('body')[0];
var log = document.getElementById('log');
var wdiv = document.getElementById('wallet');
var tdiv = document.getElementById('tx');
var floating = document.getElementById('floating');
var send = document.getElementById('send');
var newaddr = document.getElementById('newaddr');
var chainState = document.getElementById('state');
var cb = bcoin.spawn.cb;
var items = [];
var scrollback = 0;
var logger, node, options;

body.onmouseup = function() {
  floating.style.display = 'none';
};

floating.onmouseup = function(ev) {
  ev.stopPropagation();
  return false;
};

function show(obj) {
  floating.innerHTML = escape(utils.inspectify(obj, false));
  floating.style.display = 'block';
}

logger = new bcoin.logger({ level: 'debug' });
logger.writeConsole = function(level, args) {
  var msg = utils.format(args, false);
  if (++scrollback > 1000) {
    log.innerHTML = '';
    scrollback = 1;
  }
  log.innerHTML += '<span style="color:blue;">' + utils.now() + '</span> ';
  if (level === 'error')
    log.innerHTML += '<span style="color:red;">[' + level + ']</span> ';
  else
    log.innerHTML += '[' + level + '] ';
  log.innerHTML += escape(msg) + '\n';
  log.scrollTop = log.scrollHeight;
};

send.onsubmit = function(ev) {
  var value = document.getElementById('amount').value;
  var address = document.getElementById('address').value;

  var options = {
    outputs: [{
      address: address,
      value: utils.satoshi(value)
    }]
  };

  cb(node.wallet.createTX(options), function(err, tx) {
    if (err)
      return node.logger.error(err);

    cb(node.wallet.sign(tx), function(err) {
      if (err)
        return node.logger.error(err);

      cb(node.sendTX(tx), function(err) {
        if (err)
          return node.logger.error(err);

        show(tx);
      });
    });
  });

  ev.preventDefault();
  ev.stopPropagation();
  return false;
};

newaddr.onmouseup = function() {
  cb(node.wallet.createReceive(), function(err) {
    if (err)
      throw err;
    formatWallet(node.wallet);
  });
};

function kb(size) {
  size /= 1000;
  return size.toFixed(2) + 'kb';
}

function create(html) {
  var el = document.createElement('div');
  el.innerHTML = html;
  return el.firstChild;
}

function escape(html, encode) {
  return html
    .replace(!encode ? /&(?!#?\w+;)/g : /&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function addItem(tx) {
  var el;

  if (items.length === 20) {
    el = items.shift();
    tdiv.removeChild(el);
    el.onmouseup = null;
  }

  el = create('<a style="display:block;" href="#'
    + tx.rhash + '">' + tx.rhash + ' (' + tx.height
    + ' - ' + kb(tx.getSize()) + ')</a>');
  tdiv.appendChild(el);

  el.onmouseup = function(ev) {
    show(tx);
    ev.stopPropagation();
    return false;
  };

  items.push(el);

  chainState.innerHTML = ''
    + 'tx=' + node.chain.db.state.tx
    + ' coin=' + node.chain.db.state.coin
    + ' value=' + utils.btc(node.chain.db.state.value);
}

function formatWallet(wallet) {
  var html = '';
  var key = wallet.master.toJSON().key;
  html += '<b>Wallet</b><br>';
  if (bcoin.network.get().type === 'segnet4') {
    html += 'Current Address (p2wpkh): <b>' + wallet.getAddress() + '</b><br>';
    html += 'Current Address (p2wpkh behind p2sh): <b>' + wallet.getProgramAddress() + '</b><br>';
  } else {
    html += 'Current Address: <b>' + wallet.getAddress() + '</b><br>';
  }
  html += 'Extended Private Key: <b>' + key.xprivkey + '</b><br>';
  html += 'Mnemonic: <b>' + key.mnemonic.phrase + '</b><br>';
  cb(wallet.getBalance(), function(err, balance) {
    if (err)
      throw err;

    html += 'Confirmed Balance: <b>' + utils.btc(balance.confirmed) + '</b><br>';
    html += 'Unconfirmed Balance: <b>' + utils.btc(balance.unconfirmed) + '</b><br>';
    html += 'Balance: <b>' + utils.btc(balance.total) + '</b><br>';

    cb(wallet.getHistory(), function(err, txs) {
      if (err)
        throw err;

      cb(wallet.toDetails(txs), function(err, txs) {
        if (err)
          throw err;

        html += 'TXs:\n';
        wdiv.innerHTML = html;

        txs.forEach(function(tx) {
          var el = create('<a style="display:block;" href="#' + tx.hash + '">' + tx.hash + '</a>');
          wdiv.appendChild(el);
          el.onmouseup = function(ev) {
            show(tx.toJSON());
            ev.stopPropagation();
            return false;
          };
        });
      });
    });
  });
}

options = bcoin.config({
  query: true,
  network: 'segnet4',
  db: 'leveldb',
  useWorkers: true,
  coinCache: true,
  logger: logger
});

bcoin.set(options);

node = new bcoin.fullnode(options);

node.on('error', function(err) {
  ;
});

node.chain.on('block', addItem);
node.mempool.on('tx', addItem);

cb(node.open(), function(err) {
  if (err)
    throw err;

  node.startSync();

  formatWallet(node.wallet);

  node.wallet.on('update', function() {
    formatWallet(node.wallet);
  });
});

})();
