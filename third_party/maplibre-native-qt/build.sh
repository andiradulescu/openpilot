#!/usr/bin/env bash
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null && pwd)"

ARCHNAME=$(uname -m)
MAPLIBRE_FLAGS="-DMLN_QT_WITH_LOCATION=OFF"
if [ -f /AGNOS ]; then
  ARCHNAME="larch64"
  #MAPLIBRE_FLAGS="$MAPLIBRE_FLAGS -DCMAKE_SYSTEM_NAME=Android -DANDROID_ABI=arm64-v8a"
fi

cd $DIR
if [ ! -d maplibre ]; then
  git clone --single-branch https://github.com/maplibre/maplibre-native-qt.git $DIR/maplibre
fi

cd maplibre
git checkout 3726266e127c1f94ad64837c9dbe03d238255816
git submodule update --depth=1 --recursive --init

# requirement to build
sudo apt install libqt5opengl5-dev

# build
mkdir -p build
cd build
set -x
cmake $MAPLIBRE_FLAGS $DIR/maplibre
make -j$(nproc) || make -j2 || make -j1

INSTALL_DIR="$DIR/$ARCHNAME"
rm -rf $INSTALL_DIR/lib $INSTALL_DIR/include $DIR/include
mkdir -p $INSTALL_DIR/lib $INSTALL_DIR/include $DIR/include
cp -Prv $DIR/maplibre/build/src/core/*.so* $INSTALL_DIR/lib
cp -r $DIR/maplibre/build/src/core/include/* $INSTALL_DIR/include
cp -r $DIR/maplibre/src/**/*.hpp $DIR/include
