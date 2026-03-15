## Doubly Efficient Fuzzy Private Set Intersection for High-dimensional Data with Cosine Similarity

### Installation(`CPET_SEAL`)

```bash
git clone https://github.com/CPET-lab/CPET_SEAL.git
cd CPET_SEAL

cmake -S . -B build \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX=install

cmake --build build --config Release
cmake --install build
```
### Build/Run
```bash
cmake -S . -B build
cmake --build build
./build/FPHE
```

### Parameter settings
- ```src/main.cpp```

## Original README
- Hyunjung Son, Seunghun Paik, Yunki Kim, Sunpill Kim, Heewon Chung, and Jae Hong Seo
- https://eprint.iacr.org/2025/054

### Introduction

This repository provides a Python implementation of our paper using [OpenFHE](https://github.com/openfheorg/openfhe-python).

### Experimental Environment

Every experiment was performed in the following environment.

- **CPU** : AMD EPYC 7543P CPU (32 cores with 64 threads; 2.8 GHz)
- **RAM** : 512GB

To test the protocol, run the following command:

```
$ python3 test_protocol.py
```
