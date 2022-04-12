#!/bin/bash
#
# Copyright (C) 2021 CrowdStrike Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

OSM_GPS_REPO="https://github.com/nzjrs/osm-gps-map"

set -x
set -e

SRC_DIR="${PWD}"
TMP_DIR=$(mktemp -d -p "/dev/shm")
RELEASE_DIR="${SRC_DIR}/../files"

cd "${TMP_DIR}"
git clone "${OSM_GPS_REPO}"
cd $(basename "${OSM_GPS_REPO}")
GIT_DIR="${PWD}"

git checkout ee781bd5cd14148b4fda73b668f20cede7a3f228

(while read PATCH ; do git am "${PATCH}" ; done ) <<< $(find "${SRC_DIR}" -name "*.patch")

./autogen.sh
make -j 8

mkdir -p "${RELEASE_DIR}"

cp "${GIT_DIR}"/examples/mapviewer.ui "${RELEASE_DIR}"
cp "${GIT_DIR}"/examples/.libs/mapviewer "${RELEASE_DIR}"
cp "${GIT_DIR}"/src/.libs/libosmgpsmap-1.0.so.1 "${RELEASE_DIR}"
cp "${SRC_DIR}"/poi.svg "${RELEASE_DIR}"
#cp "${SRC_DIR}"/deploy.sh "${RELEASE_DIR}"

rm -rf "${TMP_DIR}"

echo -e "***\n*** Building done. Transfer RELEASE/ to challenge VM and run ./deploy.sh!\n***"
