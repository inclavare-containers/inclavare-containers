FROM registry.centos.org/centos:7

LABEL maintainer="Ding Ma <ding.ma@linux.alibaba.com>"

ENV https_proxy=$https_proxy

RUN yum -y update && yum install -y \
    autoconf \
    automake \
    binutils \
    chrony \
    coreutils \
    curl \
    gcc \
    gcc-c++ \
    git \
    glibc-common \
    glibc-devel \
    glibc-headers \
    glibc-static \
    glibc-utils \
    libseccomp \
    libseccomp-devel \
    libstdc++-devel \
    libstdc++-static \
    m4 \
    make \
    sed \
    tar \
    vim \
    which

# musl
RUN pushd /root;  \
    curl -sLO https://www.musl-libc.org/releases/musl-1.1.23.tar.gz; \
    tar -zxf musl-1.1.23.tar.gz; 	\
    cd musl-1.1.23; 	\
    sed -i "s/^ARCH = .*/ARCH = x86_64/g" dist/config.mak; 	\
    ./configure > /dev/null 2>&1; 	\
    make > /dev/null 2>&1; 	\
    make install > /dev/null 2>&1; 	\
    echo "/usr/local/musl/lib" > /etc/ld-musl-x86_64.path; 	\
    popd

ENV PATH=$PATH:/usr/local/musl/bin

# go
RUN cd /tmp ; curl -OL https://storage.googleapis.com/golang/go1.14.4.linux-amd64.tar.gz
RUN tar -C /usr/ -xzf /tmp/go1.14.4.linux-amd64.tar.gz
ENV GOROOT=/usr/go
ENV PATH=$PATH:$GOROOT/bin:$GOPATH/bin

# rust
RUN curl --proto '=https' --tlsv1.2 https://sh.rustup.rs -sSLf --output /tmp/rust-init;     \
    chmod a+x /tmp/rust-init; 	\
    /tmp/rust-init -y --default-toolchain 1.47.0

RUN . /root/.cargo/env; 	\
    cargo install cargo-when; 	\
    rustup target install x86_64-unknown-linux-musl

RUN ln -sf /usr/bin/g++ /bin/musl-g++