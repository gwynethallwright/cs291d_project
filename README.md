# cs291d_project

version:python3

## installation


clone the project with all the submodules (C++ dependencies)
```
git clone --recurse-submodules git@github.com:gwynethallwright/cs291d_project.git
```

checkout the branch with zkSNARK
```
git checkout snark
```

install Python dependencies
```
pip install -r requirements.txt
```

fix dedencency
```
add this line to the top of circuit-pour/depends/libsnark/depends/libff/CMakeLists.txt
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
```

### build C++ project
at the `circuit-pour` directory, run:
```
cmake -S . -B build
cmake --build build
```

### test the C++ project
go to `circuit-pour\build\src` and run
```
main # this generate the key to pk.bin and vk.bin.
main 1 2 3 3 3 # this reads pk.bin, generates proof, and writes it to proof.bin. the first number is the public value, the rest are coin values.
main 1 # this uses vk.bin to checks proof in proof.bin. The last line of the output should be verify_proof(): verified.
```

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

- circuit.py: setup, prove and verify NP statement POUR. Connects to circuit-pour via ctypes.
- cryptographic_basics.py: func of sig and enc
- mint.py: transaction of mint and verify
- pour.py: transaction of pour and verify
- receive.py
- tools.py: hash function, including prf, crh, sha256

in directory `circuit-pour`

- main.cpp: a C++ program that tests the circuit constructed in pour.cpp
- pour.cpp & pour.hpp: The circuit for POUR

## transaction data flow
Transaction(object) -> bytes -> (send by socket) -> bytes -> Transaction(object)

tx mine to get a block
block of mint tx has 2 txs, [mint tx, tx]

## block data flow
Block(object) -> bytes -> (send by socket) -> bytes -> Block(object)

## mine work flow
hash(str(transaction_list), etc)

## merkle tree

 Q1:
 [·]128 denotes that we are truncating the 256-bit string to 128 bits (say, by dropping leastsignificant bits, as in our implementation).
