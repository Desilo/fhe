# Open Source DESILO FHE

This is an open-source variant of the DESILO FHE library, implemented independently from the production library.


The CKKS fully homomorphic encryption scheme is supported, including a wide range of encrypted arithmetic operations and bootstrapping.
CPU parallelization is also supported for improved performance.

For the optimized, production-ready version, install the [DESILO FHE package from PyPI](https://pypi.org/project/desilofhe/).
GPU-accelerated versions are also available.
For more information, see the [DESILO FHE documentation](https://fhe.desilo.dev/latest/).

## Requirement Setup

### CPU Environment

```{sh}
sudo apt install clang-format-18 cmake
```

## Submodule Setup

```{sh}
git submodule update --init --recursive

# tag: v1.17.0 (52eb810)
cd extern/googletest
cmake -S . -B build -DBUILD_GMOCK=OFF
cmake --build build -j
```

## Compile

```{sh}
./compile.py -g -j
```

## Lint

```{sh}
./lint.sh
```

## Test

```{sh}
./test.py
```

## License

This project is licensed under The Clear BSD License.
See [LICENSE](LICENSE) for the full text.
