const HtmlWebPackPlugin = require('html-webpack-plugin');
const Dotenv = require('dotenv-webpack');

const dotEnv = new Dotenv();
const demoHtml = new HtmlWebPackPlugin({
  chunks: ['demo/index'],
  filename: './demo/index.html',
  minify: true,
  template: './demo/index.html',
});

module.exports = {
  devtool: 'source-map',
  devServer: {
    // host: "example.com",
    port: 8080,
    https: false,
  },
  entry: {
    index: './src/index.js',
    'demo/index': './demo/src/index.js',
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
  plugins: [dotEnv, demoHtml],
};
