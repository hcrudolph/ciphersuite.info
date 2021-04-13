#!/bin/bash

python3 manage.py migrate
python3 manage.py loaddata directory/fixtures/*
python3 manage.py scrapeiana
python3 manage.py filltlsversion
python3 manage.py updatesecurity
python3 manage.py compilescss
python3 manage.py collectstatic -c --noinput -v 0
python3 manage.py compress
python3 manage.py collectstatic --noinput -v 0
