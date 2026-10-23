#!/bin/bash
set -e
cd /var/www
python3 -m http.server 80
