FROM debian:bullseye@sha256:43ef0c6c3585d5b406caa7a0f232ff5a19c1402aeb415f68bcd1cf9d10180af8

ENV LC_ALL=C.UTF-8 LANG=C.UTF-8
ENV DEBIAN_FRONTEND=noninteractive

# Debian 11 is end-of-life: every package comes from the pinned snapshot.
# ca-certificates comes first from it over plain http (apt still checks the
# signed Release files), then the https URLs are used.
COPY apt.sources.list /tmp/apt.sources.list
COPY apt.preferences /etc/apt/preferences.d/snapshot
RUN rm -f /etc/apt/sources.list.d/* /etc/apt/sources.list && \
    sed 's|https://|http://|' /tmp/apt.sources.list > /etc/apt/sources.list && \
    apt-get update -qq && \
    apt-get install -qq --yes --no-install-recommends --allow-downgrades ca-certificates && \
    mv /tmp/apt.sources.list /etc/apt/sources.list

RUN apt-get update -q && \
    apt-get install -qy --allow-downgrades \
        git \
        gettext \
        python3 \
        python3-pip \
        python3-setuptools \
        python3-venv \
        faketime \
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
