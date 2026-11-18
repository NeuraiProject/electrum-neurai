FROM debian:trixie@sha256:9c6e381421d0f48d1b8133e573f33c185ee16cbf505eda9c4a8a4791b25ea8a6

ENV LC_ALL=C.UTF-8 LANG=C.UTF-8
ENV DEBIAN_FRONTEND=noninteractive

# Pin the distro packages: only the snapshot below is used, never the live
# Debian repos. ca-certificates comes first from the snapshot over plain http
# (apt still checks the signed Release files), then the https URLs are used.
COPY apt.sources.list /tmp/apt.sources.list
COPY apt.preferences /etc/apt/preferences.d/snapshot
RUN rm -f /etc/apt/sources.list.d/* /etc/apt/sources.list && \
    sed 's|https://|http://|' /tmp/apt.sources.list > /etc/apt/sources.list && \
    apt-get update -qq && \
    apt-get install -qq --yes --no-install-recommends --allow-downgrades ca-certificates && \
    mv /tmp/apt.sources.list /etc/apt/sources.list

RUN dpkg --add-architecture i386 && \
    apt-get update -q && \
    apt-get install -qy --allow-downgrades \
        wget \
        gnupg \
        dirmngr \
        python3 \
        git \
        make \
        mingw-w64 \
        mingw-w64-tools \
        autotools-dev \
        autoconf \
        autopoint \
        libtool \
        gettext \
        sudo \
        nsis \
        && \
    rm -rf /var/lib/apt/lists/* && \
    apt-get autoremove -y && \
    apt-get clean

# Wine from WineHQ (the 32-bit Windows Python runs in it, hence i386 too)
RUN mkdir -p -m 755 /etc/apt/keyrings && \
    wget -nc -O /etc/apt/keyrings/winehq-archive.key https://dl.winehq.org/wine-builds/winehq.key && \
        echo "d965d646defe94b3dfba6d5b4406900ac6c81065428bf9d9303ad7a72ee8d1b8 /etc/apt/keyrings/winehq-archive.key" | sha256sum -c - && \
    echo "deb [arch=amd64,i386 signed-by=/etc/apt/keyrings/winehq-archive.key] https://dl.winehq.org/wine-builds/debian/ trixie main" \
        > /etc/apt/sources.list.d/winehq.list && \
    apt-get update -q && \
    apt-get install -qy --allow-downgrades \
        wine-stable-amd64:amd64=11.0.0.0~trixie-1 \
        wine-stable-i386:i386=11.0.0.0~trixie-1 \
        wine-stable:amd64=11.0.0.0~trixie-1 \
        winehq-stable:amd64=11.0.0.0~trixie-1 \
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
RUN chown ${USER} /opt
USER ${USER}

RUN mkdir --parents "/opt/wine64/drive_c/electrum"
