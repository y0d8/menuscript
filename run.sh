#!/usr/bin/env bash
if [ ! -f venv/bin/activate ]; then
  python3 -m venv venv
fi
source venv/bin/activate
./install.sh
menuscript
