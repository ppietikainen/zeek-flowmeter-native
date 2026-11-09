# Zeek with Flow::Meter and nothing else, built from this repository.
#
#   podman build -t flowmeter:0.1.0 .          (or docker build)
#   podman run -i --rm -v "$PWD":/o:z flowmeter:0.1.0 -r - Flow::Meter < trace.pcap
#
# The base is the Zeek project's own image, pinned by digest, so a build names
# exactly the Zeek it ran on. Override BASE for another release.
ARG BASE=docker.io/zeek/zeek:9.0.0@sha256:70733f4e540ba1608e37e00c6a93d009f79734262c9ec2ba09d90aa9abc16de5

FROM ${BASE} AS build
RUN apt-get update \
 && apt-get install -y --no-install-recommends cmake g++ make libpcap-dev libssl-dev \
 && rm -rf /var/lib/apt/lists/*
COPY . /src
WORKDIR /src
RUN ./configure && make -j"$(nproc)" && make -C build install

FROM ${BASE}
COPY --from=build /usr/local/zeek/lib/zeek/plugins/Flow_Meter /usr/local/zeek/lib/zeek/plugins/Flow_Meter
RUN zeek -N Flow::Meter
WORKDIR /o
ENTRYPOINT ["zeek"]
