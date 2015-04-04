#!/usr/bin/env python3.4

from OpenSSL import SSL, crypto
from Crypto.Util import asn1
from paramiko import transport as ssh
import socket
import argparse

parser = argparse.ArgumentParser(description='Get RSA public key details of an SSL/TLS or SSH server.', prog='RsaScan')
parser.add_argument("--ssh", action="store_true", help="remote endpoint is an SSH server", default=False)
parser.add_argument("host", help="hostname or IP address of the server")
parser.add_argument("port", type=int, help="port of the server")
parser.add_argument("--sni", metavar="name", help="Server Name Indication string")
parser.add_argument('--version', action='version', version='%(prog)s 1.0')
args = parser.parse_args()

if not args.ssh:
    ctx = SSL.Context(SSL.SSLv23_METHOD)
    conn = SSL.Connection(ctx, socket.socket(socket.AF_INET, socket.SOCK_STREAM))
    if args.sni:
        conn.set_tlsext_host_name(bytes(args.sni, 'utf8'))
    conn.connect((args.host, args.port))
    conn.do_handshake()
    chain = conn.get_peer_cert_chain()
    conn.shutdown()
    conn.close()
    
    for i in range(len(chain)):
        pub = chain[i].get_pubkey()
        if pub.type() != crypto.TYPE_RSA:
            print("Skipping chain[" + str(i) + "]: Public key type is not RSA")
            continue
        pub_asn1 = crypto.dump_privatekey(crypto.FILETYPE_ASN1, pub)
        pub_der = asn1.DerSequence()
        pub_der.decode(pub_asn1)
        sub = chain[i].get_subject()
        print("Details of chain[" + str(i) + "]:")
        print("Common Name: " + str(sub.commonName))
        print("OU Name: " + str(sub.organizationalUnitName))
        print("Modulus: " + str(pub_der[1]))
        print("Public Exponent: " + str(pub_der[2]))
    
else:
    ssh_trans = ssh.Transport((args.host, args.port))
    ssh_trans.start_client()
    host_key = ssh_trans.get_remote_server_key()
    ssh_trans.close()
    if host_key.get_name() == 'ssh-rsa':
        print("ssh modulus: " + str(host_key.n))
        print("ssh public exponent: " + str(host_key.e))
    else:
        print('ssh public key type is not RSA')

