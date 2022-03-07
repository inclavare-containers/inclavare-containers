# Develop and deploy a "Hello World" container in Kubernetes cluster

This page shows how to develop a "Hello World" application, build a "Hello World" image and run a "Hello World" container in a Kubernetes cluster.

Note: this is an experimental and demonstrative guide. Please don't deploy it in product.

## Before you begin

- You need to have a Kubernetes cluster and the nodes' hardware in the cluster must support Intel SGX. If you do not already have a cluster, you can create one following the documentation [Create a confidential computing Kubernetes cluster with inclavare-containers](create_a_confidential_computing_kubernetes_cluster_with_inclavare_containers.md).
- Make sure you have one of the following operating systems:
	- Ubuntu 18.04 server 64bits

## Objectives

- Develop a "Hello World" occlum application in an occlum SDK container.
- Build a "Hello World" image from the application.
- Run the "Hello World" Pod in Kubernetes cluster.

## Instructions

### 1. Create a Pod with occlum SDK image
Occlum supports running any executable binaries that are based on [musl libc](https://www.musl-libc.org/). It does not support Glibc. A good way to develop occlum applications is in an occlum SDK container.
You can choose one suitable occlum SDK image from the list in [this page](https://hub.docker.com/r/occlum/occlum/tags), the version of the Occlum SDK image must be same as the occlum version listed in release page.

- Step 1. Apply the following yaml file
    ```yaml
    cat << EOF | kubectl apply -f -
    apiVersion: v1
    kind: Pod
    metadata:
      labels:
        run: occlum-app-builder
      name: occlum-app-builder
      namespace: default
    spec:
      hostNetwork: true
      containers:
      - command:
        - sleep
        - infinity
        image: docker.io/occlum/occlum:0.21.0-ubuntu18.04
        imagePullPolicy: IfNotPresent
        securityContext:
          privileged: true
        name: occlum-app-builder
    EOF
    ```
    This will create a Pod with image `docker.io/occlum/occlum:0.21.0-ubuntu18.04` and the filed `securityContext.privileged` should be set to `true`  in order to build and push docker image in container.<br />

- Step 2. Wait for the pod status to `Ready`

    It will take about one minute to create the pod, you need to check and wait for the pod status to `Ready` . Run command `kubectl get pod occlum-app-builder`, the output looks like this:
    ```bash
    $ kubectl get pod occlum-app-builder
    NAME                 READY   STATUS    RESTARTS   AGE
    occlum-app-builder   1/1     Running   0          15s
    ```

- Step 3. Login the occlum-app-builder container
    ```bash
    kubectl exec -it occlum-app-builder -c occlum-app-builder -- /bin/bash
    ```

- Step 4. Install docker in the container

    Install docker following the [documentation](hhttps://docs.docker.com/engine/install/debian/). Note that the `systemd` is not installed in the container by default, so you can't manage docker service by `systemd`.

- Step 5. Start the docker service by the following command:
    ```bash
    nohup dockerd -b docker0 --storage-driver=vfs &
    ```

- Step 6. Make sure the docker service started

    Run command `docker ps`, the output should be like this:
    ```
    $ docker ps
    CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
    ```

### 2. Develop the "Hello World" application in the container
If you were to write an SGX Hello World project using some SGX SDK, the project would consist of hundreds of lines of code. And to do that, you have to spend a great deal of time to learn the APIs, the programming model, and the built system of the SGX SDK.<br />Thanks to Occlum, you can be freed from writing any extra SGX-aware code and only need to type some simple commands to protect your application with SGX transparently.

Note that the version of Linux SGX software stack must be same with the one [installed on host](https://github.com/alibaba/inclavare-containers/blob/master/docs/create_a_confidential_computing_kubernetes_cluster_with_inclavare_containers.md#2-install-linux-sgx-software-stack). Please run this command to check the version:
```shell
/opt/intel/sgxsdk/bin/x64/sgx_sign -version
```

- Step 1. Create a working directory in the container
    ```c
    mkdir /root/occlum_workspace && cd /root/occlum_workspace/
    ```

- Step 2. Write the "Hello World" code in C language：
    ```c
    cat << EOF > /root/occlum_workspace/hello_world.c
    #include <stdio.h>
    #include <unistd.h>
    
    int main() {
        while(1){
          printf("Hello World!\n");
          fflush(stdout);
          sleep(5);
        }
    }
    EOF
    ```

- Step 3. Compile the user program with the Occlum toolchain (e.g., `occlum-gcc`)
    ```bash
    occlum-gcc -o hello_world hello_world.c
    ```

- Step 4. Initialize a directory as the Occlum context via `occlum init`
    ```bash
    mkdir occlum_context && cd occlum_context
    occlum init
    ```
    The `occlum init` command creates the compile-time and run-time state of Occlum in the current working directory. The `occlum new` command does basically the same thing but in a new instance diretory. Each Occlum instance directory should be used for a single instance of an application; multiple applications or different instances of a single application should use different Occlum instances.

- Step 5. Generate a secure Occlum FS image and Occlum SGX enclave via `occlum build`
    ```bash
    cp ../hello_world image/bin/
    occlum build
    ```
    The content of the `image` directory is initialized by the `occlum init` command. The structure of the `image` directory mimics that of an ordinary UNIX FS, containing directories like `/bin`, `/lib`, `/root`, `/tmp`, etc. After copying the user program `hello_world` into `image/bin/`, the `image` directory is packaged by the `occlum build` command to generate a secure Occlum FS image as well as the Occlum SGX enclave.

The FS image is integrity protected by default, if you want to protect the confidentiality and integrity with your own key, please check out [here](https://github.com/occlum/occlum/blob/master/docs/encrypted_image.md).

- Step 6. Run the user program inside an SGX enclave via `occlum run`
    ```
    occlum run /bin/hello_world
    ```
    The `occlum run` command starts up an Occlum SGX enclave, which, behind the scene, verifies and loads the associated occlum FS image, spawns a new LibOS process to execute `/bin/hello_world`, and eventually prints the message.


### 3. Build the "Hello World" image

- Step 1. Write the Dockerfile
    ```dockerfile
    cat << EOF >Dockerfile
    FROM scratch
    ADD image /
    ENTRYPOINT ["/bin/hello_world"]
    EOF
    ```
    It is recommended that you use the scratch as the base image. The scratch image is an empty image, it makes the docker image size small enough, which means a much smaller Trusted Computing Base (TCB) and attack surface. `ADD image /` add the occlum image directory into the root directory of the docker image, `ENTRYPOINT ["/bin/hello_world"]` set the command `/bin/hello_world` as the container entry point.

- Step 2. Build and push the "Hello World" image to your docker registry

    Build and push the image to your docker registry. For example, you create a docker repository named occlum-hello-world in namespace inclavarecontainers, then you can push the image to `docker.io/inclavarecontainers/occlum-hello-world:scratch`.
    ```dockerfile
    docker build -f "Dockerfile" -t "docker.io/inclavarecontainers/occlum-hello-world:scratch" .
    docker push "docker.io/inclavarecontainers/occlum-hello-world:scratch"
    ```


### 4. Run the "Hello World" Container

If you want to run the "Hello World" Container on off-cloud signing scheme, please modify configuration as following:
    ```bash
    sed -i 's/server/client/g' /etc/inclavare-containers/config.toml
    ```

- Step 1. Create the "Hello World" Pod

    Exit from the occlum SDK container, apply the following yaml to create the "Hello World" Pod.
    ```yaml
    cat << EOF | kubectl apply -f -
    apiVersion: v1
    kind: Pod
    metadata:
      labels:
        run: helloworld
      name: helloworld
    spec:
      runtimeClassName: rune
      containers:
      - command:
        - /bin/hello_world
        env:
        - name: RUNE_CARRIER
          value: occlum
        image: docker.io/inclavarecontainers/occlum-hello-world:scratch
        imagePullPolicy: IfNotPresent
        name: helloworld
        workingDir: /var/run/rune
    EOF
    ```
    **Note**: The field `runtimeClassName` should be set to `rune` which means the container will be handled by rune, specify the environment `RUNE_CARRIER` to `occlum` telling the `shim-rune`  to create and run an occlum application.<br />
<br />You can also configure enclave through these environment variables：

    | Environment Variable Name | Default Value | Other Value |
    | --- | --- | --- |
    | OCCLUM_RELEASE_ENCLAVE | 0 (debug enclave) | 1 (product enclave) |
    | ENCLAVE_RUNTIME_LOGLEVEL | "info" | "trace", "debug", "warning", "error", "fatal", "panic", "off" |
    | OCCLUM_USER_SPACE_SIZE | 256MB | |
    | OCCLUM_KERNEL_SPACE_HEAP_SIZE | 32MB | |
    | OCCLUM_KERNEL_SPACE_STACK_SIZE | 1MB | |
    | OCCLUM_MAX_NUM_OF_THREADS | 32 | |
    | OCCLUM_PROCESS_DEFAULT_STACK_SIZE | 4MB | |
    | OCCLUM_PROCESS_DEFAULT_HEAP_SIZE | 32MB | |
    | OCCLUM_PROCESS_DEFAULT_MMAP_SIZE | 80MB | |
    | OCCLUM_DEFAULT_ENV | OCCLUM=yes | |
    | OCCLUM_UNTRUSTED_ENV | EXAMPLE | |



- Step 2. Wait for the pod status to `Ready`
    ```yaml
    kubectl get pod helloworld
    ```

- Step 3. Print the container's logs via `kubectl logs`

    Execute the command `kubectl logs -f helloworld`, a line "Hello world" will be printed on the terminal every 5 seconds. The output looks like this:
    ```
    $ kubectl logs -f helloworld
    Hello World!
    Hello World!
    Hello World!
    ```

## Cleanup

Use the following commands to delete the two pods `helloworld` and `occlum-app-builder` 
```yaml
kubectl delete pod helloworld
kubectl delete pod occlum-app-builder
```
