#include <node.h>
#include <nan.h>
#include "./functions.h"
#include <stdio.h>
#include <stdlib.h>
#include "tweetnacl.h"

typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef long long i64;
typedef i64 gf[16];

const int crypto_sign_BYTES = 64;
const int bug_offset = 64;

using v8::Local;
using v8::Object;
using v8::Boolean;
using v8::Integer;
using v8::Value;
using v8::Isolate;
using v8::HandleScope;
using v8::Array;
using v8::Uint8Array;
using Nan::ReturnValue;
using Nan::GetFunction;
using Nan::New;
using Nan::Set;

/**
* Crypto verification function (Ed25519)
*/
NAN_METHOD(verify) {
  // Reading clear message
  Local<Object> msg = info[0]->ToObject();
  u64 mlen = msg.As<Uint8Array>()->Length();
  u8* m = static_cast<u8*>(msg.As<Uint8Array>()->Buffer()->GetContents().Data());

  // Reading detached signature
  Local<Object> sig = info[1]->ToObject();

  u64 smlen = sig.As<Uint8Array>()->Length();
  const u8* sm = static_cast<u8*>(sig.As<Uint8Array>()->Buffer()->GetContents().Data());

  // Reading public key
  Local<Object> pub = info[2]->ToObject();
  const u8* pubk = static_cast<u8*>(pub.As<Uint8Array>()->Buffer()->GetContents().Data());

  // Verifying authenticity
  int res = crypto_sign_open(m,&mlen,sm,smlen,pubk);

  info.GetReturnValue().Set(New<Boolean>(res == 0));
}


/**
* Crypto signature function (Ed25519)
*/
NAN_METHOD(sign) {
  // Reading clear message
  Local<Object> msg = info[0]->ToObject();
  u64 mlen = msg.As<Uint8Array>()->Length() - bug_offset;
  const u8* m = static_cast<u8*>(msg.As<Uint8Array>()->Buffer()->GetContents().Data());
  const u8* m2 = m + bug_offset;

  // Reading public key
  Local<Object> sec = info[1]->ToObject();
  const u8* seck = static_cast<u8*>(sec.As<Uint8Array>()->Buffer()->GetContents().Data());

  u8* sm;
  u64 smlen = 0;

  sm = (u8*) malloc(mlen + crypto_sign_BYTES);

  // Signing
  crypto_sign(sm,&smlen,m2,mlen,seck);

  // Result
  Local<Object> array = New<Array>(smlen);

  for (int i = 0; i < smlen; i++) {
    array->Set(i, New<Integer>(sm[i]));
  }

  // Free memory
  free(sm);

  info.GetReturnValue().Set(array);
}
