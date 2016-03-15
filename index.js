// Exposes 2 methods: verify(msg, sig, pub), sign(msg, sec)
module.exports = new function() {

  var binary = require('node-pre-gyp');
  var path = require('path');
  var binding_path = binary.find(path.resolve(path.join(__dirname,'./package.json')));
  var binding = require(binding_path);

  this.verify = binding.verify;

  this.sign = function(m, sec) {

    var b = new Uint8Array(m.length + 64);
    var i;
    for (i = 0; i < m.length; i++) {
      b[i + 64] = m[i];
    }
    return binding.sign(b, sec);
  };
};
