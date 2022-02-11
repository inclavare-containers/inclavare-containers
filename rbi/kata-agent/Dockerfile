FROM centos:8.3.2011

LABEL maintainer="Ding Ma <ding.ma@linux.alibaba.com>"

RUN [ -n "$http_proxy" ] && sed -i '$ a proxy='$http_proxy /etc/dnf/dnf.conf ; true
RUN dnf install make git gcc -y 

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path
ENV PATH "/root/.cargo/bin:${PATH}"
RUN rustup install 1.53.0 && rustup target add x86_64-unknown-linux-musl

COPY scripts/start.sh /root

WORKDIR /root
CMD ["bash", "start.sh"]