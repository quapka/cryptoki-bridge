#!/usr/bin/env bash

cargo b --release 
# &&     ssh-keygen -D target/release/libcryptoki_bridge.so -e > meesign.pub &&     ssh-keygen -f meesign.pub -e -m pem > meesign.pub.openssl &&     openssl rsa -pubin -in meesign.pub.openssl -text -noout &&     
lxc file push target/release/libcryptoki_bridge.so demoss1/home/xroad/nix-cryptoki.so
lxc file push target/release/libcryptoki_bridge.so demoss2/home/xroad/nix-cryptoki.so
./showDER.sh
