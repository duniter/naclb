// Exposes 2 methods: verify(msg, sig, pub), sign(msg, sec)
module.exports = new function() {

  var binding = require('bindings')('nacl');

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
