# cs291d_project

version:python3

## installation (With zkSNARK)
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
add this line to the top of `circuit-pour/depends/libsnark/depends/libff/CMakeLists.txt`:
```
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
```

### build the circuit-pour C++ project
at the `circuit-pour` directory, run:
```
cmake -S . -B build
cmake --build build
```

### test the circuit-pour C++ project
go to `circuit-pour\build\src` and run these commands:

1. Generate the key to pk.bin and vk.bin.
    ```
    main
    ```
2. Read pk.bin, generate proof, and write it to proof.bin. the first number is the public value, the rest are coin values.
    ```
    main 1 2 3 3 3
    ```
3. Use vk.bin to check proof in proof.bin. If the number is the public value, the last line of the output should be verify_proof(): verified.
    ```
    main 1
    ```
    
## installation (Without zkSNARK)
clone the project
```
git clone git@github.com:gwynethallwright/cs291d_project.git
```

install Python dependencies
```
pip install -r requirements.txt
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
