#!/bin/bash

if [ ! -f build/release/t3fc ]; then
    meson build/release --buildtype release
fi
ninja -C build/release

if [ ! -f build/debug/t3fc ]; then
    meson build/debug --buildtype debug
fi
ninja -C build/debug