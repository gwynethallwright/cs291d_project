# cs291d_project

version:python3

## simple blockchian
in directory `blockchain`


### test usage
test blockchain
```
python blockchain.py
```

test wallet
```
python wallet.py
```

test node
```
python test_node.py
```
<!-- Open test_node.ipynb and run it cell by cell. For cell[10], please wait 20 seconds for the broadcast data to be fully transmitted to fully operate. -->

## zcash
in directory `zcash`

- circuit.py: setup, prove and verify of circuit of pour
- cryptographic_basics.py: func of sig and enc
- mint.py: transaction of mint and verify
- pour.py: transaction of pour and verify
- receive.py
- tools.py: hash function, including prf, crh, sha256

 Q1:
 [·]128 denotes that we are truncating the 256-bit string to 128 bits (say, by dropping leastsignificant bits, as in our implementation).