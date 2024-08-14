#!/usr/bin/env bash

export OMP_NUM_THREADS=1
export MKL_NUM_THREADS=1
export NUMEXPR_NUM_THREADS=1
export OPENBLAS_NUM_THREADS=1
export VECLIB_MAXIMUM_THREADS=1

if [ -z "$AGNOS_VERSION" ]; then
  export AGNOS_VERSION="30a7fcb89e9e5f8398c16ced7ae08626f68a3e91"
fi

export STAGING_ROOT="/data/safe_staging"
