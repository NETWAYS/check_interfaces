#!/bin/bash

set -x
set -e

apt-get update
apt-get -y install libsnmp-dev
