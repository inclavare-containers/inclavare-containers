FROM registry.fedoraproject.org/fedora:34-x86_64

LABEL maintainer="Ding Ma <ding.ma@linux.alibaba.com>"

RUN [ -n "$http_proxy" ] && sed -i '$ a proxy='$http_proxy /etc/dnf/dnf.conf ; true

RUN dnf install -y qemu-img \
                parted \
                gdisk \
                e2fsprogs \
                gcc \
                xfsprogs \
                findutils

COPY files /root
COPY scripts /root

WORKDIR /root

CMD ["bash", "start.sh"]