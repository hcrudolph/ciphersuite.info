#!/bin/bash

python3.7 manage.py migrate
python3.7 manage.py loaddata directory/fixtures/*
python3.7 manage.py scrapeiana
python3.7 manage.py filltlsversion
python3.7 manage.py updatesecurity
python3.7 manage.py compilescss
python3.7 manage.py collectstatic -c --noinput
python3.7 manage.py compress
python3.7 manage.py collectstatic --noinput
