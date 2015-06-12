var addon  = require('./../index');
var nacl   = require('tweetnacl');
var base58 = require('./../base58');
var assert = require('assert');

var pub = "HgTTJLAQ5sqfknMq7yLPZbehtuLSsKj9CxWN7k8QvYJd";
var sec = "51w4fEShBk1jCMauWu4mLpmDVfHksKmWcygpxriqCEZizbtERA6de4STKRkQBpxmMUwsKXRjSzuQ8ECwmqN1u2DP";
var msg  = "UID:CAT\nMETA:TS:1411321474\n";
var msg2 = "UID:COT\nMETA:TS:1411321474\n";
var msg3 = "UID:CUT\nMETA:TS:1411321474\n";
var sig = "YvMQqaOAgLtnJzg5ZGhI17sZvXjGgzpSMxNz8ikttMspU5/45MQAqnOfuJnfbrzkkspGlUUjDnUPsOmHPcVyBQ==";

var crypto_sign_BYTES = 64;

var longMessage  = '01234567890123456789012345678901234567890123456789012345678912345'; // 65 chars
var shortMessage = '0123';

describe('Crypto', function() {

  it('should success on verify', function() {
    assert(verifySync(msg, sig, pub));
  });

  it('should fail if not verifying', function() {
    assert(verifySync("some wrong message", sig, pub) == false);
    assert(verifySync(msg3, sig, pub) == false);
    assert(verifySync("UID:CAT\nMETA:TS:1411321474\n", sig, pub));
    assert(verifySync("UID:CAT\nMETA:TS:1411321474\r\n", sig, pub) == false);
  });

  it('should success on sign of more than 64 characters', function() {
    var sig = signSync(longMessage, sec);
    assert.equal(verifySync(longMessage, sig, pub), true);
  });

  it('should success on sign less than 64 characters', function() {
    var sig = signSync(shortMessage, sec);
    assert.equal(verifySync(shortMessage, sig, pub), true);
  });
});

function signSync(msg, sec) {
  var m = nacl.util.decodeUTF8(msg);
  var signedMsg = addon.sign(m, base58.decode(sec));
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