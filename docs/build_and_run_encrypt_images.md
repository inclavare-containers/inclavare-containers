This guide shows how to build and run encryption images.

# Tools

- [skopeo](https://github.com/containers/skopeo)  
  `skopeo` is a command line utility that performs various operations on container images and image repositories.
- [containerd v1.5.3](https://github.com/containerd/containerd/tree/v1.5.3)  
  `containerd` is an industry-standard container runtime with an emphasis on simplicity, robustness and portability. It also provides the following tools. 
    - `crictl`: `crictl` provides a CLI for CRI-compatible container runtimes. This allows the CRI runtime developers to debug their runtime without needing to set up Kubernetes components.
    - `ctd-decoder`: `ctd-decoder` is use by containerd to decrypt encrypted container images.
- [ctr-enc](https://github.com/containerd/imgcrypt)  
  `ctr-enc` is used to encrypt and decrypt container images is also provided. 
- [simple-ocicrypt-keyprovider](https://github.com/lumjjb/simple-ocicrypt-keyprovider)  
  `simple-ocicrypt-keyprovider` is an external binary program to provide key.

The above tools are already built in the development image `inclavarecontainers/dev-eaa:$version-ubuntu18.04`, please type the following command to run the development image directly.

```shell
docker run -it --rm --privileged --net host \
  inclavarecontainers/dev-eaa:$version-ubuntu18.04
```

# Instructions

The following steps describe how to start a pod running the encrypted container image.

## Prepare a sample image to encrypt 

Prepare a sample image to encrypt or use an already built image from any public/private registry by pulling it into a local repository. The image should be oci complaint.

```shell
skopeo --insecure-policy copy docker://docker.io/library/alpine:latest oci:alpine
```

## Encrypt the image

There are two methods to encrypt the images: recipient encryption key and key provider (Binary executable and gRPC).

### Recipient encryption key

Please type the following command to generate key pair.

```shell
openssl genrsa --out mykey.pem
openssl rsa -in mykey.pem -pubout -out mypubkey.pem
cp -f mykey.pem /etc/containerd/ocicrypt/keys/
```

Encrypt the image as follows.

```shell
skopeo copy --insecure-policy --encryption-key jwe:./mypubkey.pem \
  oci:alpine oci:alpine-encrypted-recipient-key
```

Decrypt the image as follows (Skip this step in development).

```
skopeo copy --insecure-policy --decryption-key mykey.pem \
  oci:alpine-encrypted-recipient-key oci:alpine-decrypted-recipient-key
```

### key provider (Binary executable)

[simple-ocicrypt-keyprovider](https://github.com/lumjjb/simple-ocicrypt-keyprovider) is a sample Golang application that you can build as a binary executable. In a sample image encryption, `simple-ocicrypt-keyprovider` encrypts the symmetric key passed from the ocicrypt key provider protocol. You can use the same application to decrypt the sample encrypted image, where it decrypts the wrapped key and returns the image decryption key back to the key provider protocol.

Encrypt the image as follows.

```shell
OCICRYPT_KEYPROVIDER_CONFIG=/etc/containerd/ocicrypt/ocicrypt_keyprovider.conf skopeo \
  copy --insecure-policy --encryption-key provider:simplecrypt:test \
  oci:alpine oci:alpine-encrypted-key-provider
```

Decrypt the image as follows (Skip this step in development).

```shell
OCICRYPT_KEYPROVIDER_CONFIG=/etc/containerd/ocicrypt/ocicrypt_keyprovider.conf skopeo \
  copy --insecure-policy --decryption-key provider:simplecrypt:extra-params \
  oci:alpine-encrypted-key-provider oci:alpine-decrypted-key-provider
```

### key provider (gRPC)

TODO

## Push encryption images to docker hub

```shell
# login to docker hub
skopeo login docker.io --username <$username> --password <$password>

# push the images to docker hub
skopeo copy --insecure-policy --dest-tls-verify=false \
  oci:alpine-encrypted-recipient-key docker://<$username>/alpine-encrypted-recipient-key:latest
skopeo copy --insecure-policy --dest-tls-verify=false \
  oci:alpine-encrypted-key-provider docker://<$username>/alpine-encrypted-key-provider:latest
```

## Start containerd

```shell
containerd &
```

## Generate pod configuration file

```shell
cat << EOF >pod.yaml
metadata:
  attempt: 1
  name: my-podsandbox
  namespace: default
  uid: hdishd83djaidwnduwk28bcsb
log_directory: /tmp/eaa_test
linux:
  namespaces:
    options: {}
EOF
```

## Generate container configuration file

```shell
cat << EOF >container.yaml
metadata:
  name: alpine.enc
image:
  image: <$TARGET_IMAGE>
command:
- top
log_path: busybox.0.log
EOF
```

The variable <$TARGET_IMAGE> specifies the image address. You can use image `<$username>/alpine-encrypted-key-provider:latest` or `<$username>/alpine-encrypted-recipient-key:latest`.

## Run pod and container

```shell
crictl run container.yaml pod.yaml
```

## Test the pod

```shell
crictl ps
CONTAINER           IMAGE                                            CREATED             STATE               NAME                ATTEMPT             POD ID
2d0414e875912       <$user_name>/alpine-encrypted-recipient-key:latest   4 seconds ago       Running             alpine.enc          0                   cc584e4876a66

crictl exec 2d0414e875912 echo "Hello, world!!"
Hello, world
```

## Clean the pod and container

```shell
# show the running pod id
crictl pods
POD ID              CREATED             STATE                    
49a4b66cd4af8       18 minutes ago      Ready            

# stop and clean pods
crictl stopp POD-ID
crictl rmp POD-ID
```

In addition, you can also use the `ctr-enc` tool to build and run an encrypted image.

# Usage of `ctr-enc`

Please skip this skep in the development. These steps are just an experimental demonstration.

Start containerd with a configuration file that looks like the following example. To avoid interference with a containerd from a Docker installation, use `/tmp` for directories.

```shell
cat << EOF >config.toml
disable_plugins = ["cri"]
root = "/tmp/var/lib/containerd"
state = "/tmp/run/containerd"
[grpc]
  address = "/tmp/run/containerd/containerd.sock"
  uid = 0
  gid = 0
EOF

containerd -c config.toml &
```

Create an RSA key pair using the openssl command-line tool and encrypt an image.

```shell
openssl genrsa --out mykey.pem
openssl rsa -in mykey.pem -pubout -out mypubkey.pem
CTR="/usr/local/bin/ctr-enc -a /tmp/run/containerd/containerd.sock"
$CTR images pull --all-platforms docker.io/library/alpine:3.4
$CTR images encrypt --recipient jwe:mypubkey.pem --platform linux/amd64 docker.io/library/alpine:3.4 alpine.enc:3.4
```

Run the encrypted container image.

```shell
$CTR run --rm --snapshotter=native alpine.enc:3.4 test echo "hello, world"
ctr: you are not authorized to use this image: missing private key needed for decryption

$CTR run --rm --snapshotter=native --key mykey.pem alpine.enc:3.4 test echo "hello, world"
hello, world
```

# Trouble Shooting

In the docker environment, ctr-enc returns an error when pulling some images. This problem is related to the content of the pulled images. There is no better solution at present. Please use alpine images instead. The error is as follows:

```
$CTR images pull --all-platforms docker.io/library/bash:latest
 unpacking linux/amd64 sha256:a2ec07de39cf5efd201ceb04403e1762ea296fb1c5d4b7e2175c11c8bf0b7f71...
INFO[0002] apply failure, attempting cleanup             error="failed to extract layer sha256:051cf7304fe61d2e6345db31754f03af61e6fb5f270cfbf0c207b460d4ed4e0e: failed to convert whiteout file \"etc/terminfo/.wh..wh..opq\": operation not supported: unknown" key="extract-875200990-A1Iq sha256:a144b09ae0eff7b4cee5e33458531e4d8b9c7e131c2f70281d03d035ca711761"
```

# Reference

- [enabling-advanced-key-usage-and-management-in-encrypted-container-images](https://developer.ibm.com/articles/enabling-advanced-key-usage-and-management-in-encrypted-container-images/)
- [encrypted-container-images-for-container-image-security-at-rest](https://developer.ibm.com/articles/encrypted-container-images-for-container-image-security-at-rest/)
