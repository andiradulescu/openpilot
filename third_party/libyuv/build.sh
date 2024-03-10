#!/usr/bin/env bash
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null && pwd)"

ARCHNAME=$(uname -m)
if [ -f /TICI ]; then
  ARCHNAME="larch64"
fi

cd $DIR
if [ ! -d libyuv ]; then
  git clone https://chromium.googlesource.com/libyuv/libyuv
fi

cd libyuv
git reset --hard 4a14cb2e81235ecd656e799aecaaf139db8ce4a2
cmake .
make -j$(nproc)

INSTALL_DIR="$DIR/$ARCHNAME"
cp $DIR/libyuv/libyuv.a $INSTALL_DIR/lib
cp -r $DIR/libyuv/include/* $DIR/include

## To create universal binary on Darwin:
## ```
## lipo -create -output Darwin/libyuv.a path-to-x64/libyuv.a path-to-arm64/libyuv.a
## ```
