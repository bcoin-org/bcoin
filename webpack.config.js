'use strict';

var webpack = require('webpack')
var path = require('path');

module.exports = {
  target: 'web',
  entry: {
    'bcoin': './lib/bcoin-browser',
    'bcoin-master': './lib/workers/master'
  },
  output: {
    path: path.resolve(__dirname, 'browser'),
    filename: '[name].js'
  },
  resolve: {
    modules: ['node_modules'],
    extensions: ['-browser.js', '.js', '.json']
  },
  module: {
    rules: [{
      test: /\.js$/,
      exclude: path.resolve(__dirname, 'node_modules'),
      loader: 'babel-loader'
    }]
  },
  plugins: [
    new webpack.optimize.UglifyJsPlugin({
      compress: {
        warnings: false
      }
    })
  ]
};
