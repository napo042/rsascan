# RsaScan v1.0
RsaScan is tool for finding interesting properties of RSA public keys of SSL/TLS and SSH servers. As of v1.0, features include:
- SSH as well as SSL servers
- RSA keys in the whole PKI chain of SSL servers
- Server Name Indication (SNI) support

Prerequisites:
- Python >= 3.4
- pyOpenSSL >= 0.14
- PyCrypto >= 2.6
- Paramiko >= 1.15
