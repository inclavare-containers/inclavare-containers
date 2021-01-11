# Inclavare Containers Roadmap

This document provides the roadmap of Inclavare Containers project.

- v0.5.0: Initial K8s confidential computing cluster
- v1.0.0: Full function of K8s confidential computing cluster

## rune

- (0.6.0) Code refactoring for minimizing the dependency on libcontainer.
- (0.7.0) Leave this CLI to using docker.

## libenclave & runelet

- Implement Enclave VMM to launch the enclave in form of confidential VM based on vSGX (0.8.0) technologies.

## shim-rune

- (0.7.0) Integrate libenclave and libcontainer.

## Enclave Runtimes

- Support more enclave runtimes such as [Graphene](https://github.com/oscarlab/graphene)(0.7.0), [WAMR](https://github.com/bytecodealliance/wasm-micro-runtime)(0.5.0), [sgx-lkl](https://github.com/lsds/sgx-lkl)(0.8.0), [enarx](https://github.com/enarx/enarx)(0.9.0), [openenclave](https://github.com/openenclave/openenclave)(1.0.0) and so on.
- (0.8.0) Provide a reference Enclave OS for confidential VM.

## Enclave Pooling Manager

- (0.5.0) Implement bundle cache and enclave pooling for dramatically speeding up enclave launch time.

## shelter

- (0.5.0) kubectl plugin for confidential K8s management.

## shelterd

- (0.8.0) Daemon server for shelter clients.

## enclaved & stub enclave

- (0.5.0) Implement general attestation service and infrastructure for confidential Kubernetes.
