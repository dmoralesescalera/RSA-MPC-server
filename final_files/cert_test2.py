from oscrypto import asymmetric
from certbuilder import CertificateBuilder, pem_armor_certificate
import binascii
import socket


# Conectar con el servidor MPC y generar claves
#s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#s.connect(('127.0.0.1', 5000))
#s.send('g')
#public_key = s.recv(33)
f = open("../viff/apps/pub_key.txt")
root_ca_public_key = f.readline()
#if(s.recv(1) == 'o'):
root_ca_public_key = asymmetric.load_public_key(binascii.unhexlify(root_ca_public_key))
print root_ca_public_key
#root_ca_public_key = asymmetric.load_public_key(u'../viff/apps/pub_key.txt')

builder = CertificateBuilder(
    {
        u'country_name': u'US',
        u'state_or_province_name': u'Massachusetts',
        u'locality_name': u'Newbury',
        u'organization_name': u'Codex Non Sufficit LC',
        u'common_name': u'CodexNS Root CA 1',
    },
    root_ca_public_key
)
builder.self_signed = True
builder.ca = True
# root_ca_private_key tiene que ser un entero (identificador de la clave privada)
root_ca_certificate = builder.build(1234)

with open('root_ca.crt', 'wb') as f:
    f.write(pem_armor_certificate(root_ca_certificate))

'''
# Generate an end-entity key and certificate, signed by the root
end_entity_public_key, end_entity_private_key = asymmetric.generate_pair('rsa', bit_size=2048)

with open('will_bond.key', 'wb') as f:
    f.write(asymmetric.dump_private_key(end_entity_private_key, u'password'))

builder = CertificateBuilder(
    {
        u'country_name': u'US',
        u'state_or_province_name': u'Massachusetts',
        u'locality_name': u'Newbury',
        u'organization_name': u'Codex Non Sufficit LC',
        u'common_name': u'Will Bond',
    },
    end_entity_public_key
)
builder.issuer = root_ca_certificate
end_entity_certificate = builder.build(root_ca_private_key)

with open('will_bond.crt', 'wb') as f:
    f.write(pem_armor_certificate(end_entity_certificate))
'''
