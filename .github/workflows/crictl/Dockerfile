FROM centos:8.1.1911

RUN mkdir -p /run/rune
WORKDIR /run/rune

ADD occlum_instance.tar.gz /run/rune

ENTRYPOINT ["/bin/hello_world"]
