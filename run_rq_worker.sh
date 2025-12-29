#!/usr/bin/env bash
set -euo pipefail

export MONOLITH_QUEUE=${MONOLITH_QUEUE:-rq}
python3 -m cyberapp.workers.rq_worker
