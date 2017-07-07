'use strict';

const webpack = require('webpack')
const path = require('path');
const UglifyJsPlugin = require('uglifyjs-webpack-plugin');
const str = JSON.stringify;
const env = process.env;

module.exports = {
  target: 'web',
  entry: {
    'bcoin': './lib/bcoin-browser',
    'bcoin-worker': './lib/workers/worker'
  },
  output: {
    path: path.join(__dirname, 'browser'),
    filename: '[name].js'
  },
  resolve: {
    modules: ['node_modules'],
    extensions: ['-browser.js', '.js', '.json']
  },
  plugins: [
    new webpack.DefinePlugin({
      'process.env.BCOIN_NETWORK':
        str(env.BCOIN_NETWORK || 'main'),
      'process.env.BCOIN_WORKER_FILE':
        str(env.BCOIN_WORKER_FILE || '/bcoin-worker.js')
    }),
    new UglifyJsPlugin({
      compress: {
        warnings: true
      }
    })
  ]
};
