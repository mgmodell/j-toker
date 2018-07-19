const Dotenv = require('dotenv-webpack');

const dotenv = new Dotenv();

module.exports = {
  devtool: 'source-map',
  devServer: {
    // host: "example.com",
    port: 8080,
    https: false,
  },
  entry: './src/index.js',
  output: {
    path: __dirname + '/dist',
    filename: 'index.js',
    library: 'esToker',
    libraryTarget: 'umd',
    umdNamedDefine: true,
  },
  module: {
    rules: [
      {
        test: /\.js$/,
        exclude: /node_modules/,
        use: {
          loader: 'babel-loader',
        },
      },
    ],
  },
  plugins: [dotenv],
};
