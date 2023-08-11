#!/usr/bin/python

import datetime
from ansible.errors import AnsibleError
from ansible.module_utils.basic import AnsibleModule
from cryptography.hazmat.primitives.asymmetric import rsa

HAVE_PYJWT = False
try:
    import jwt
    from jwt.algorithms import RSAAlgorithm
    HAVE_PYJWT = True
except ImportError:
    pass

DOCUMENTATION = r'''
---
module: generate

short_description: Generate a JWKS along with a valid JWT

description: This module generates a JWKS containing a single JWK, along with a signed JWT which never expires

options:
    issuer:
        description: JWKS issuer
        required: true
        type: str
    subject:
        description: JWKS subject
        required: true
        type: str
    expiry:
        description: JWT expiration in days after generation. Token will not expire if this option is not set.
        required: false
        type: int
    public_exponent:
        description: public exponent parameter for RSA key generation
        required: false
        type: int
    key_size:
        description: key size parameter for RSA key generation
        required: false
        type: int

author:
    - Hugues Granger (@huguesgr)
'''

EXAMPLES = r'''
- name: Test JWKS generation
  huguesgr.jwks_jwt.generate:
    issuer: myissuer
    subject: mysubject
    expiry: 3600
'''

RETURN = r'''
jwks:
    description: JWKS
    type: str
    returned: always
    sample: '{"keys":[{"kty": "RSA", "key_ops": ["verify"], "n": "u8iLUp71u3y59jAWsBHLPwcnXY9Dugu-7YtBb9LXYHnYa6FcLiY7asQC7i8eOkXK4x2I-P5Wh-05NnRxVbJMR_VF0oMtGKpbeqoHmNdfrcAF87Y5xMTX4s9YA9Ii_6XMvdHvrX03XWWTrKvY_RD9YYjMCUIC309TmunZxFqh_EXW6sBAgmkpzgcFLiw_rzwQ0diqE9uQZlDqnV3jcBd0wOQqV9D-A59sen8tkR1GM-5VtxlNWv_9ztQQvOg-tdjLYaEh8ST6qi15MkNGea2HidYqDpKOzYbwUGBbIofq1lShhssZQ_3hOU84ANg6OjNrg7bB3mfDJtudGyGVXmSiCQ", "e": "AQAB"}]}'
jwt:
    description: JWT signed with JWKS
    type: str
    returned: always
    sample: 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJobGFiIiwic3ViIjoiaGxhYiJ9.PT2VfFyLCWLICdRwbAk0riCxAvz5F7uWHQin7mlwJgJhQ9RhfAvK9awJi3H3PCS-9QD_v2RbQ0QobuOyOxtku7-FU72FLVjL9XVIhHS_dWT0gaiqm2IQbLJmXrqGKzY6SEAe0zqOUFG5TBeyObYjyfo8XOnFmNsDMldsERlcP95bDbuaEtlPLPtkagnoiIeZtlq-p4qEFg55NVSsEE1CARy1BGvHetHYUpYhHWLFtFioqkr88BU8SOqB7LkaLn0tHZbWJXcHjjvNFMogUgye_0RD7MSGPSo0_jNp6RTE_zm0N81SbUmuz0ly_nM8EQ8bYjWI0h4AgTWw1YBH3Qkvrg'
'''


def generate(issuer: str, subject: str, public_exponent: int, key_size: int, expiry: int) -> dict:
    payload = {
        "iss": issuer,
        "sub": subject,
    }
    if expiry != 0:
        payload['exp'] = int(round((datetime.datetime.now() + datetime.timedelta(days=expiry)).timestamp()))

    private_key = rsa.generate_private_key(
        public_exponent=public_exponent,
        key_size=key_size,
    )
    public_key = private_key.public_key()

    algo = RSAAlgorithm(RSAAlgorithm.SHA256)
    jwk = algo.to_jwk(public_key)

    res = {}
    res["jwks"] = "{\"keys\":["+jwk+"]}"
    res["jwt"] = jwt.encode(payload, private_key, algorithm="RS256")

    return res


def run_module():
    module = AnsibleModule(
        argument_spec=dict(
            issuer=dict(type="str", required=True),
            subject=dict(type="str", required=True),
            public_exponent=dict(type="int", required=False, default=65537),
            key_size=dict(type="int", required=False, default=2048),
            expiry=dict(type="int", required=False, default=0),
        )
    )

    result = dict(
        changed=True,
        jwks="",
        jwt="",
    )

    if not HAVE_PYJWT:
        raise AnsibleError("Library PyJWT is not installed")

    if module.check_mode:
        module.exit_json(**result)

    issuer = module.params["issuer"]
    subject = module.params["subject"]
    public_exponent = module.params["public_exponent"]
    key_size = module.params["key_size"]
    expiry = module.params["expiry"]
    result = generate(issuer, subject, public_exponent, key_size, expiry)

    module.exit_json(**result)


def main() -> None:
    run_module()


if __name__ == "__main__":
    main()
