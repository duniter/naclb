var addon  = require('./');
var nacl   = require('tweetnacl');
var base58 = require('./base58');
var assert = require('assert');

var rawPub = "HgTTJLAQ5sqfknMq7yLPZbehtuLSsKj9CxWN7k8QvYJd";
var rawMsg = "UID:CAT\nMETA:TS:1411321474\n";
var rawSig = "YvMQqaOAgLtnJzg5ZGhI17sZvXjGgzpSMxNz8ikttMspU5/45MQAqnOfuJnfbrzkkspGlUUjDnUPsOmHPcVyBQ==";
var rawSec = "51w4fEShBk1jCMauWu4mLpmDVfHksKmWcygpxriqCEZizbtERA6de4STKRkQBpxmMUwsKXRjSzuQ8ECwmqN1u2DP";

var msg = nacl.util.decodeUTF8(rawMsg);
var sig = nacl.util.decodeBase64(rawSig);
var pub = base58.decode(rawPub);
var sec = base58.decode(rawSec);

const crypto_sign_BYTES = 64;
// checkArrayTypes(msg, sig, publicKey);
// if (sig.length !== crypto_sign_BYTES)
//   throw new Error('bad signature size');
// if (publicKey.length !== crypto_sign_PUBLICKEYBYTES)
//   throw new Error('bad public key size');
var start = new Date();
var sm = new Uint8Array(crypto_sign_BYTES + msg.length);
var m = new Uint8Array(crypto_sign_BYTES + msg.length);
var i;
for (i = 0; i < crypto_sign_BYTES; i++) sm[i] = sig[i];
for (i = 0; i < msg.length; i++) sm[i+crypto_sign_BYTES] = msg[i];

var longMessage  = '01234567890123456789012345678901234567890123456789012345678912345'; // 65 chars
var shortMessage = '0123';

describe('Crypto', function() {

  it('should success on verify', function() {
    assert(addon.verify(m, sm, pub) == true);
  });

  it('should success on sign of more than 64 characters', function() {
    var sig = signSync(longMessage, sec);
    assert.equal(verifySync(longMessage, sig, rawPub), true);
  });

  it('should success on sign less than 64 characters', function() {
    var sig = signSync(shortMessage, sec);
    assert.equal(verifySync(shortMessage, sig, rawPub), true);
  });
});

function signSync(msg, sec) {
  var m = nacl.util.decodeUTF8(msg);
  var signedMsg = addon.sign(m, sec);
  var sig = new Uint8Array(crypto_sign_BYTES);
  for (var i = 0; i < sig.length; i++) sig[i] = signedMsg[i];
  return nacl.util.encodeBase64(sig);
}

function verifySync(rawMsg, rawSig, rawPub) {
  var msg = nacl.util.decodeUTF8(rawMsg);
  var sig = nacl.util.decodeBase64(rawSig);
  var pub = base58.decode(rawPub);
  var m = new Uint8Array(crypto_sign_BYTES + msg.length);
  var sm = new Uint8Array(crypto_sign_BYTES + msg.length);
  var i;
  for (i = 0; i < crypto_sign_BYTES; i++) sm[i] = sig[i];
  for (i = 0; i < msg.length; i++) sm[i+crypto_sign_BYTES] = msg[i];
  return addon.verify(m, sm, pub);
}