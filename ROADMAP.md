# Inclavare Containers Roadmap

This document provides the roadmap of Inclavare Containers project.

## rune

- Code refactoring for minimizing the dependency on libcontainer. 
- Leave this CLI to using docker.

## libenclave

- Implement Enclave VMM to launch the enclave in form of confidential VM based on vSGX, SEV and TDX technologies.

## shim-rune

- Integrate libenclave and libcontainer. 

## Enclave Runtime

- Support more enclave runtimes such as [WAMR](https://github.com/bytecodealliance/wasm-micro-runtime), [sgx-lkl](https://github.com/lsds/sgx-lkl), [enarx](https://github.com/enarx/enarx), [openenclave](https://github.com/openenclave/openenclave) and so on.
- Provide a reference Enclave OS for confidential VM. 

## Enclave Pooling Manager

- Implement bundle cache and enclave pooling for dramatically speeding up enclave launch time.

## Enclave Attestation Infrastructure

- Implement general attestation service and infrastructure for confidential Kubernetes.
