# Note: we deliberately use an old Debian stable as base image.
# from https://docs.appimage.org/introduction/concepts.html :
# "[AppImages] should be built on the oldest possible system, allowing them to run on newer system[s]"
# Debian 11 (glibc 2.31): the AppImage runs on Ubuntu 20.04+, Debian 11+, Mint 20+...
# Debian 11 is end-of-life, so its live repos are not used at all: every
# package comes from the pinned snapshot.

FROM debian:bullseye@sha256:6f519a81440354a85eb592c5f32109ab80605f6b892455983a6f618bf87fabe9

ENV LC_ALL=C.UTF-8 LANG=C.UTF-8
ENV DEBIAN_FRONTEND=noninteractive

# Pin the distro packages. ca-certificates comes first from the snapshot over
# plain http (apt still checks the signed Release files), then the https URLs
# are used.
COPY apt.sources.list /tmp/apt.sources.list
COPY apt.preferences /etc/apt/preferences.d/snapshot
RUN rm -f /etc/apt/sources.list.d/* /etc/apt/sources.list && \
    sed 's|https://|http://|' /tmp/apt.sources.list > /etc/apt/sources.list && \
    apt-get update -qq && \
    apt-get install -qq --yes --no-install-recommends --allow-downgrades ca-certificates && \
    mv /tmp/apt.sources.list /etc/apt/sources.list

RUN apt-get update -q && \
    apt-get install -qy --allow-downgrades \
        sudo \
        cmake \
        g++ \
        git \
        wget \
        make \
        autotools-dev \
        autoconf \
        libtool \
        autopoint \
        pkg-config \
        xz-utils \
        libssl-dev \
        libssl1.1 \
        openssl \
        zlib1g-dev \
        libffi-dev \
        libncurses5-dev \
        libncurses5 \
        libtinfo-dev \
        libtinfo5 \
        libsqlite3-dev \
        libusb-1.0-0-dev \
        libudev-dev \
        libudev1 \
        gettext \
        libzbar0 \
        libdbus-1-3 \
        xutils-dev \
        libxkbcommon0 \
        libxkbcommon-x11-0 \
        libxcb1-dev \
        libxcb-xinerama0 \
        libxcb-randr0 \
        libxcb-render0 \
        libxcb-shm0 \
        libxcb-shape0 \
        libxcb-sync1 \
        libxcb-xfixes0 \
        libxcb-xkb1 \
        libxcb-icccm4 \
        libxcb-image0 \
        libxcb-keysyms1 \
        libxcb-util1 \
        libxcb-render-util0 \
        libx11-xcb1 \
        libc6-dev \
        libc6 \
        libc-dev-bin \
        && \
    rm -rf /var/lib/apt/lists/* && \
    apt-get autoremove -y && \
    apt-get clean

# create new user to avoid using root; but with sudo access and no password for convenience.
ARG UID=1000
ENV USER="user"
ENV HOME_DIR="/home/${USER}"
ENV WORK_DIR="${HOME_DIR}/wspace" \
    PATH="${HOME_DIR}/.local/bin:${PATH}"
RUN useradd --uid $UID --create-home --shell /bin/bash ${USER}
RUN usermod -append --groups sudo ${USER}
RUN echo "%sudo ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
WORKDIR ${WORK_DIR}
RUN chown --recursive ${USER} ${WORK_DIR}
USER ${USER}
