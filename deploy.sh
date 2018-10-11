#!/bin/bash

python3.6 manage.py migrate
python3.6 manage.py loaddata directory/fixtures/*
python3.6 manage.py scrapeiana
python3.6 manage.py filltlsversion
python3.6 manage.py collectstatic -c --noinput
