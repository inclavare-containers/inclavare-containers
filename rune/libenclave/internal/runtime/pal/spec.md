# Enclave Runtime PAL API Specification

## Introduction

Enclave Runtime PAL API defines a common interface to interact between rune and enclave runtime.

## Versions

Enclave Runtime PAL API Specification currently support [PAL API v1](https://github.com/alibaba/inclavare-containers/blob/master/rune/libenclave/internal/runtime/pal/spec_v1.md) and [PAL API v2](https://github.com/alibaba/inclavare-containers/blob/master/rune/libenclave/internal/runtime/pal/spec_v2.md).

If you want to use `rune` to run your enclave runtime, you can choose one of supported PAL API version to achieve. Using higher PAL API is recommended.

The PAL API will evolve. You can submit proposal for the extension of PAL API. We will take it after careful consideration.

## The relationship between `rune` and PAL APIs

`rune` has a lot of subcommands such as `create`,`start`,`exec`,`run`,`kill`,`delete`, and etc. The relationship between them is shown in the following table.

| Subcommand | v1 | v2 |
| :-------:  | :-------:  |  :-------: |
| create | pal_get_version | pal_get_version |
|		| pal_init | pal_init |
| start | pal_exec | pal_create_process |
|		|            | pal_exec |
| run  |  pal_get_version  | pal_get_version |
|	   | pal_init |  pal_init |
|      |  pal_exec | pal_create_process |
|	  |                | pal_exec |
|      | pal_destroy | pal_destroy | 
| exec | pal_exec  | pal_create_process |
|      |           | pal_exec           | 
| delete | pal_destroy | pal_destroy |
| kill |  |  pal_kill |

## Enclave Runtime Programming Guide

If you want to develop a PAL for your enclave runtime, please refer to [Enclave Runtime Programming Guide](https://github.com/alibaba/inclavare-containers/blob/master/rune/docs/pal_programming_guide.md) for the details.

Current enclave runtime programming guide version is based on PAL API v2.
