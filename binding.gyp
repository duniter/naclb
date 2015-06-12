{
  "targets": [
    {
      "target_name": "nacl",
      "sources": [ "nacl.cc", "functions.cc", "tweetnacl.cpp", "randombytes.cpp"],
      "include_dirs" : [
         "<!(node -e \"require('nan')\")"
      ]
    }
  ]
}
