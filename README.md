# ciphersuite.info ![Travis CI build status](https://travis-ci.org/hcrudolph/ciphersuite.info.svg?branch=master)

## What is this project?

A directory of every cipher suite defined by the IETF. Each cipher suite is broken down to its containing algorithms whose security is then individually assessed. Different warnings are generated based on the severity of known vulnerabilities.

## Whom is this project targeting?

This project aims to be a general reference regarding the security of TLS cipher suites. That said, it should be a resource both for security experts and developers with knowledge about crypto as well as non-experts searching for a clear representation about whether a certain algorithm is sufficiently secure or not.

## Where is the data from?

All cipher suites and their defining RFCs are automatically scraped from the [IANA TLS Cipher Suite Registry](https://www.iana.org/assignments/tls-parameters/tls-parameters.xml#tls-parameters-4). The evaluation of cryptographic algorithms is - where possible - based on official notices by the IETF or other organizations. Since the security aspects of certain technologies may vary based on the specific use case, this is not always unambiguous. In these cases a recommendation is given for which purposes this technology is ok to use or whether the authors of this website consider it unsafe.
