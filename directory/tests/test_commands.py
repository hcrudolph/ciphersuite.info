import directory.management.commands.importvulnerabilities as iv
from directory.models import Vulnerability
from django.test import TestCase


class ImportvulnerabilitiesTest(TestCase):
    vulnerabilities_file = './vulnerabilities.csv'
    defined_vulnerabilities = []

    def prepare_comparison(self):
        with open(self.vulnerabilities_file, 'r') as f:
            for line in f.readlines():
                if not line.startswith('#'):
                    n, s, d = line.rstrip().split(';')
                    self.defined_vulnerabilities.append(
                        (n.strip(), s.strip(), d.strip())
                    )

    def setUp(self):
        self.prepare_comparison()
        args = []
        opts = {'file_path': self.vulnerabilities_file}
        cmd = iv.Command()
        cmd.handle(*args, **opts)

    def test_created_objects(self):
        for vuln in self.defined_vulnerabilities:
            v = Vulnerability.objects.get(name=vuln[0])
            self.assertEqual(v.severity.__str__(), vuln[1])
            self.assertEqual(v.description.__str__(), vuln[2])
