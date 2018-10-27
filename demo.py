import jwt
from jwksutils import rsa_pem_from_jwk

# To run this example, follow the instructions in the project README

# obtain jwks as you wish: configuration file, HTTP GET request to the endpoint returning them;
jwks = {
    "keys": [
        {
            "kid": "X5eXk4xyojNFum1kl2Ytv8dlNP4-c57dO6QGTVBwaNk",
            "nbf": 1493763266,
            "use": "sig",
            "kty": "RSA",
            "e": "AQAB",
            "n": "tVKUtcx_n9rt5afY_2WFNvU6PlFMggCatsZ3l4RjKxH0jgdLq6CScb0P3ZGXYbPzXvmmLiWZizpb-h0qup5jznOvOr-Dhw9908584BSgC83YacjWNqEK3urxhyE2jWjwRm2N95WGgb5mzE5XmZIvkvyXnn7X8dvgFPF5QwIngGsDG8LyHuJWlaDhr_EPLMW4wHvH0zZCuRMARIJmmqiMy3VD4ftq4nS5s8vJL0pVSrkuNojtokp84AtkADCDU_BUhrc2sIgfnvZ03koCQRoZmWiHu86SuJZYkDFstVTVSR0hiXudFlfQ2rOhPlpObmku68lXw-7V-P7jwrQRFfQVXw"
        }
    ]
}

# configuration, these can be seen in valid JWTs from Azure B2C:
valid_audiences = ['d7f48c21-2a19-4bdb-ace8-48928bff0eb5'] # id of the application prepared previously
issuer = 'https://ugrose.b2clogin.com/9c2984ff-d596-4e5c-8e74-672be7b592e3/v2.0/' # iss


class InvalidAuthorizationToken(Exception):
    def __init__(self, details):
        super().__init__('Invalid authorization token: ' + details)


def get_kid(token):
    headers = jwt.get_unverified_header(token)
    if not headers:
        raise InvalidAuthorizationToken('missing headers')
    try:
        return headers['kid']
    except KeyError:
        raise InvalidAuthorizationToken('missing kid')


def get_jwk(kid):
    for jwk in jwks.get('keys'):
        if jwk.get('kid') == kid:
            return jwk
    raise InvalidAuthorizationToken('kid not recognized')


def get_public_key(token):
    return rsa_pem_from_jwk(get_jwk(get_kid(token)))


def validate_jwt(jwt_to_validate):
    public_key = get_public_key(jwt_to_validate)

    decoded = jwt.decode(jwt_to_validate,
                         public_key,
                         verify=True,
                         algorithms=['RS256'],
                         audience=valid_audiences,
                         issuer=issuer)

    # do what you wish with decoded token:
    # if we get here, the JWT is validated
    print(decoded)


def main():
    import sys
    import traceback

    if len(sys.argv) < 2:
        print('Please provide a JWT as script argument')
        return
    
    jwt = sys.argv[1]

    if not jwt:
        print('Please pass a valid JWT')

    try:
        validate_jwt(jwt)
    except Exception as ex:
        traceback.print_exc()
        print('The JWT is not valid!')
    else:
        print('The JWT is valid!')


if __name__ == '__main__':
    main()
