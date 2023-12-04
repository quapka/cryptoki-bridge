#!/usr/bin/env bash

# convert
python DERhex2bin.py

openssl rsa -pubin -noout -text -in key.der
