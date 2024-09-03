#!/usr/bin/env bash

export OMP_NUM_THREADS=1
export MKL_NUM_THREADS=1
export NUMEXPR_NUM_THREADS=1
export OPENBLAS_NUM_THREADS=1
export VECLIB_MAXIMUM_THREADS=1

if [ -z "$AGNOS_VERSION" ]; then
  export AGNOS_VERSION="4049ecee55542c71e4c00b7c60a80162a0e41eed"
fi

export STAGING_ROOT="/data/safe_staging"
