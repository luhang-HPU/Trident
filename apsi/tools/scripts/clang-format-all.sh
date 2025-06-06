#!/bin/bash

BASE_DIR=$(dirname "$0")
APSI_ROOT_DIR=$BASE_DIR/../../
shopt -s globstar
clang-format -i $APSI_ROOT_DIR/**/*.h
clang-format -i $APSI_ROOT_DIR/**/*.c
clang-format -i $APSI_ROOT_DIR/**/*.cpp
