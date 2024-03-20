#!/bin/bash

set -xe

# for compilation deps and rootless containers
dnf install -y libasan slirp4netns

# build image
podman build -t http_server .

# add user id mappings to run rootless inside container
usermod --add-subuids 100000-165535 --add-subgids 100000-165535 terminull

# run image inside container with port mapping in detached mode, removing after
# killed
# podman run -d -p 8080:8080 --name http_server http_server
