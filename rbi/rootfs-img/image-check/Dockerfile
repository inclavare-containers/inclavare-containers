FROM registry.fedoraproject.org/fedora:34-x86_64

LABEL maintainer="Ding Ma <ding.ma@linux.alibaba.com>"

RUN [ -n "$http_proxy" ] && sed -i '$ a proxy='$http_proxy /etc/dnf/dnf.conf ; true

RUN dnf install -y qemu-img-2:5.2.0-8.fc34.x86_64 \
                parted-3.4-2.fc34.x86_64 \
                gdisk-1.0.8-1.fc34.x86_64 \
                e2fsprogs-1.45.6-5.fc34.x86_64 \
                gcc-11.1.1-3.fc34.x86_64 \
                xfsprogs-5.10.0-2.fc34.x86_64 \
                findutils-1:4.8.0-2.fc34.x86_64

COPY files /root
COPY scripts /root

WORKDIR /root

CMD ["bash", "start.sh"]