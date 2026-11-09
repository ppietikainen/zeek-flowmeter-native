# Zeek with Flow::Meter and nothing else, built from this repository.
#
#   podman build -t flowmeter:0.1.0 .          (or docker build)
#   podman run -i --rm -v "$PWD":/o:z flowmeter:0.1.0 -r - Flow::Meter < trace.pcap
#
# The base is the Zeek project's own image, pinned by digest, so a build names
# exactly the Zeek it ran on. Override BASE for another release.
ARG BASE=docker.io/zeek/zeek:9.0.1@sha256:524cb0ce29f26a6a954fb9c357a8f92b95812476d8240f0ece26617ace249dd0

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
