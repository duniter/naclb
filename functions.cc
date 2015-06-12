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

/**
* Crypto verification function (Ed25519)
*/
NAN_METHOD(verify) {
  NanScope();

  // Reading clear message
  Local<Object> msg = args[0]->ToObject();
  u64 mlen = msg->GetIndexedPropertiesExternalArrayDataLength();
  u8* m = static_cast<u8*>(msg->GetIndexedPropertiesExternalArrayData());

  // Reading detached signature
  Local<Object> sig = args[1]->ToObject();

  u64 smlen = sig->GetIndexedPropertiesExternalArrayDataLength();
  const u8* sm = static_cast<u8*>(sig->GetIndexedPropertiesExternalArrayData());

  // Reading public key
  Local<Object> pub = args[2]->ToObject();
  const u8* pubk = static_cast<u8*>(pub->GetIndexedPropertiesExternalArrayData());

  // Verifying authenticity
  int res = crypto_sign_open(m,&mlen,sm,smlen,pubk);

  NanReturnValue(NanNew<Boolean>(res == 0));
}


/**
* Crypto signature function (Ed25519)
*/
NAN_METHOD(sign) {
  NanScope();

  // Reading clear message
  Local<Object> msg = args[0]->ToObject();
  u64 mlen = msg->GetIndexedPropertiesExternalArrayDataLength() - bug_offset;
  const u8* m = static_cast<u8*>(msg->GetIndexedPropertiesExternalArrayData());
  const u8* m2 = m + bug_offset;

  // Reading public key
  Local<Object> sec = args[1]->ToObject();
  const u8* seck = static_cast<u8*>(sec->GetIndexedPropertiesExternalArrayData());

  u8* sm;
  u64 smlen = 0;

  sm = (u8*) malloc(mlen + crypto_sign_BYTES);

  // Signing
  crypto_sign(sm,&smlen,m2,mlen,seck);

  // Result
  Local<Object> array = NanNew<Array>(smlen);

  for (int i = 0; i < smlen; i++) {
    array->Set(i, NanNew<Integer>(sm[i]));
  }

  // Free memory
  free(sm);

  NanReturnValue(array);
}
