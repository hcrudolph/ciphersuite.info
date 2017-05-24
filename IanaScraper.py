#!/usr/bin/python3

import re
import sys
import requests
from bs4 import BeautifulSoup

##################################################

# ./manage.py shell

# from directory.models import *
# from IanaScraper import IanaScraper

# iana = IanaScraper()
# rec = iana.get_rfc_dicts()
# for e in rec:
#     c, _ = CipherSuite.objects.get_or_create(
#         name=e['name'],
#         hex_byte_1=e['hex1'],
#         hex_byte_2=e['hex2'],
#     )
#     r, _ = Rfc.objects.get_or_create(
#         number=e['rfc'],
#     )
#     c.defining_rfcs.add(r)

##################################################

class ResourceNotFoundException(Exception):
    pass


class IanaScraper:
    def __init__(self, url="https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml"):
        self.url = url


    def get(self, url):
        """Sends a HTTP request to the given URL. If the status code
        of its response is not equal 200, a ResourceNotFoundException
        is raised."""

        response = requests.get(url)
        if response.status_code != 200:
            raise ResourceNotFoundException(
                "Resource not found under the given URL."
            )
        else:
            return response


    def get_url_content(self, url):
        """Tries to fetch a given URL and return the textual contents
        of the respective HTTP response. If retreiving the web page
        fails, an Exception is raised an an empty text returned."""

        try:
            resp = self.get(url)
        except ResourceNotFoundException as e:
            print(e.message)
            return ""
        return resp.text


    def get_rfc_dicts(self):
        """Parses the IANA TLS paramter table for RFC information. List of all
        table contents can be parsed with the filter_dict funciton. Returns a
        list of dicts, where each dict contains the information on one row."""

        page = BeautifulSoup(
            self.get_url_content(self.url),
            'html.parser'
        )
        contents = self.parse_table(page)
        contents = self.filter_dict(contents, 'hex1', r'^0x[0123456789ABCDEF]{2}$')
        contents = self.filter_dict(contents, 'hex2', r'^0x[0123456789ABCDEF]{2}$')
        contents = self.filter_dict(contents, 'name', r'.*WITH.*')
        contents = self.filter_dict(contents, 'rfc', r'\d+')
        return contents


    def filter_dict(self, list_of_dicts, key, regex):
        """Filters out all items in the given list_of_dicts whose value
        under the specified key does not match the regular expression."""

        return [x for x in list_of_dicts if re.match(regex, x[key])]


    def parse_table(self, page):
        """Parses the table id 'table-tls-parameters-4'."""
        parsed_contents = []
        table = page.find(id="table-tls-parameters-4")
        for row in table.tbody.find_all('tr'):
            result = dict()
            for nr, cell in enumerate(row.find_all('td')):
                if nr == 0:
                    try:
                        hex_codes = cell.contents[0].split(',')
                        result['hex1'] = hex_codes[0].strip()
                        result['hex2'] = hex_codes[1].strip()
                    except IndexError:
                        contents = ""
                elif nr == 1:
                    try:
                        result['name'] = cell.contents[0].strip()
                    except IndexError:
                        contents = ""
                elif nr == 2:
                    try:
                        result['dtls'] = cell.contents[0].strip()
                    except IndexError:
                        contents = ""
                elif nr == 3:
                    try:
                        contents = cell.contents[1]
                        match = re.search(">RFC(\d+)</a>", str(contents))
                        result['rfc'] = match.group(1)
                    except (IndexError, AttributeError):
                        result['rfc'] = ""

            parsed_contents.append(result)
        return parsed_contents

