# EC_Crypto

Elliptic-curve digital signing & verifying C implement
It tries to implement in C code with openssl lib as the shell does:

##shell
```
#!/bin/bash
#private key
openssl ecparam -name secp256k1 -genkey -out _priv.pem
openssl ec -in _priv.pem -text -noout

# public key
openssl ec -in _priv.pem -pubout -out _pub.pem
openssl ec -in _pub.pem -pubin -text -noout
openssl ec -in _pub.pem -pubin -text -noout -conv_form compressed

# sign
FILE="_msg"

/bin/cat <<EOM >$FILE
Protected message
EOM
openssl dgst -sha256 -sign _priv.pem _msg >_sig.der
# hexdump _sig.der 

# verify
openssl dgst -sha256 -verify _pub.pem -signature _sig.der _msg
```

