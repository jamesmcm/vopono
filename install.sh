#!/bin/sh

cargo install --path .
mkdir -p ${HOME}/.config/vopono
cp -r ./configuration/* ${HOME}/.config/vopono/

