#include <node.h>
#include <nan.h>
#include "functions.h"

using v8::FunctionTemplate;
using v8::Handle;
using v8::Object;
using v8::String;

void InitAll(Handle<Object> exports) {

  exports->Set(NanNew<String>("verify"),
    NanNew<FunctionTemplate>(verify)->GetFunction());

  exports->Set(NanNew<String>("sign"),
    NanNew<FunctionTemplate>(sign)->GetFunction());
}

NODE_MODULE(nacl, InitAll)
