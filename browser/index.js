;(function() {

'use strict';

var util = bcoin.util;
var body = document.getElementsByTagName('body')[0];
var log = document.getElementById('log');
var wdiv = document.getElementById('wallet');
var tdiv = document.getElementById('tx');
var floating = document.getElementById('floating');
var send = document.getElementById('send');
var newaddr = document.getElementById('newaddr');
var chainState = document.getElementById('state');
var rpc = document.getElementById('rpc');
var cmd = document.getElementById('cmd');
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
  floating.innerHTML = escape(util.inspectify(obj, false));
  floating.style.display = 'block';
}

logger = new bcoin.logger({ level: 'debug' });
logger.writeConsole = function(level, args) {
  var msg = util.format(args, false);
  if (++scrollback > 1000) {
    log.innerHTML = '';
    scrollback = 1;
  }
  log.innerHTML += '<span style="color:blue;">' + util.now() + '</span> ';
  if (level === 'error')
    log.innerHTML += '<span style="color:red;">[' + level + ']</span> ';
  else
    log.innerHTML += '[' + level + '] ';
  log.innerHTML += escape(msg) + '\n';
  log.scrollTop = log.scrollHeight;
};

rpc.onsubmit = function(ev) {
  var text = cmd.value || '';
  var argv = text.trim().split(/\s+/);
  var method = argv.shift();
  var params = [];
  var i, arg, param;

  cmd.value = '';

  for (i = 0; i < argv.length; i++) {
    arg = argv[i];
    try {
      param = JSON.parse(arg);
    } catch (e) {
      param = arg;
    }
    params.push(param);
  }

  node.rpc.execute({ method: method, params: params }).then(show, show);

  ev.preventDefault();
  ev.stopPropagation();

  return false;
};

send.onsubmit = function(ev) {
  var value = document.getElementById('amount').value;
  var address = document.getElementById('address').value;
  var tx, options;

  options = {
    outputs: [{
      address: address,
      value: bcoin.amount.value(value)
    }]
  };

  node.wallet.createTX(options).then(function(mtx) {
    tx = mtx;
    return node.wallet.sign(tx);
  }).then(function() {
    return node.sendTX(tx);
  }).then(function() {
    show(tx);
  });

  ev.preventDefault();
  ev.stopPropagation();

  return false;
};

newaddr.onmouseup = function() {
  node.wallet.createReceive().then(function() {
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

  setMouseup(el, tx);

  items.push(el);

  chainState.innerHTML = ''
    + 'tx=' + node.chain.db.state.tx
    + ' coin=' + node.chain.db.state.coin
    + ' value=' + bcoin.amount.btc(node.chain.db.state.value);
}

function setMouseup(el, obj) {
  el.onmouseup = function(ev) {
    show(obj);
    ev.stopPropagation();
    return false;
  };
}

function formatWallet(wallet) {
  var html = '';
  var key = wallet.master.toJSON(true).key;
  var i, tx, el;

  html += '<b>Wallet</b><br>';

  if (wallet.account.witness) {
    html += 'Current Address (p2wpkh): <b>'
      + wallet.getAddress()
      + '</b><br>';
    html += 'Current Address (p2wpkh behind p2sh): <b>'
      + wallet.getNestedAddress()
      + '</b><br>';
  } else {
    html += 'Current Address: <b>' + wallet.getAddress() + '</b><br>';
  }

  html += 'Extended Private Key: <b>' + key.xprivkey + '</b><br>';
  html += 'Mnemonic: <b>' + key.mnemonic.phrase + '</b><br>';

  wallet.getBalance().then(function(balance) {
    html += 'Confirmed Balance: <b>'
      + bcoin.amount.btc(balance.confirmed)
      + '</b><br>';

    html += 'Unconfirmed Balance: <b>'
      + bcoin.amount.btc(balance.unconfirmed)
      + '</b><br>';

    return wallet.getHistory();
  }).then(function(txs) {
    return wallet.toDetails(txs);
  }).then(function(txs) {
    html += 'TXs:\n';
    wdiv.innerHTML = html;

    for (i = 0; i < txs.length; i++) {
      tx = txs[i];

      el = create(
        '<a style="display:block;" href="#' + tx.hash + '">'
        + tx.hash + '</a>');

      wdiv.appendChild(el);
      setMouseup(el, tx.toJSON());
    }
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
node.rpc = new bcoin.rpc(node);

node.on('error', function(err) {
  ;
});

node.chain.on('block', addItem);
node.mempool.on('tx', addItem);

node.open().then(function() {
  node.startSync();

  formatWallet(node.wallet);

  node.wallet.on('balance', function() {
    formatWallet(node.wallet);
  });
});

})();
