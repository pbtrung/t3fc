#!/bin/bash

if [ ! -f build/release/sk ]; then
    meson build/release --buildtype release
fi
ninja -C build/release

if [ ! -f build/debug/sk ]; then
    meson build/debug --buildtype debug
fi
ninja -C build/debug