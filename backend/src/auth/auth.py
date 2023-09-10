import json
from flask import request, _request_ctx_stack
from functools import wraps
from jose import jwt
from urllib.request import urlopen
import os

AUTH0_URL = os.environ.get("AUTH0_URL")
AUDIENCE = os.environ.get("AUTH0_AUDIENCE")

AUTH0_DOMAIN = AUTH0_URL
ALGORITHMS = ['RS256']
API_AUDIENCE = AUDIENCE

'''
AuthError Exception
A standardized way to communicate auth failure modes
'''
class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


## Auth Header
def get_token_auth_header():
    # Get the header from the request
    auth_header = request.headers.get('Authorization', None)
    # Raise an AuthError if no header is present
    if not auth_header:
        raise AuthError({"code": "authorization_header_missing",
            "description": "Authorization header is expected."}, 401)

    # Split bearer and the token
    parts = auth_header.split()
    if parts[0].lower() != 'bearer':
        raise AuthError({"code": "invalid_header",
            "description": "Authorization header must start with 'Bearer'."}, 401)

    elif len(parts) == 1:
        raise AuthError({"code": "invalid_header",
            "description": "Token not found."}, 401)

    elif len(parts) > 2:
        raise AuthError({"code": "invalid_header",
            "description": "Authorization header must be 'Bearer <token>'."}, 401)

    # Return the token part of the header
    token = parts[1]
    return token


def check_permissions(permission, payload):
    print(permission, 'permission')
    print(payload, 'payload')
    
    if 'permissions' not in payload:
        raise AuthError({"code": "invalid_claims",
            "description": "Permissions not included in JWT."}, 400)

    if permission not in payload['permissions']:
        raise AuthError({"code": "unauthorized",
            "description": "Permission not found."}, 403)
    
    return True

def verify_decode_jwt(token):
    # Get the public key from Auth0
    jsonurl = urlopen(f'https://{AUTH0_DOMAIN}/.well-known/jwks.json')
    jwks = json.loads(jsonurl.read())

    # Decode the payload from the token
    unverified_header = jwt.get_unverified_header(token)
    rsa_key = {}
    
    if 'kid' not in unverified_header:
        raise AuthError({"code": "invalid_header", "description": "Authorization malformed."}, 401)

    for key in jwks['keys']:
        if key['kid'] == unverified_header['kid']:
            rsa_key = {
                "kty": key['kty'],
                "kid": key['kid'],
                "use": key['use'],
                "n": key['n'],
                "e": key['e']
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=API_AUDIENCE,
                issuer='https://' + AUTH0_DOMAIN + '/'
            )
            return payload

        except jwt.ExpiredSignatureError:
            raise AuthError({"code": "token_expired", "description": "Token expired."}, 401)

        except jwt.JWTClaimsError:
            raise AuthError({"code": "invalid_claims",
                "description": "Incorrect claims. Please, check the audience and issuer."}, 401)
        except Exception:
            raise AuthError({"code": "invalid_header",
                "description": "Unable to parse authentication token."}, 400)
    
    raise AuthError({"code": "invalid_header",
        "description": "Unable to find the appropriate key."}, 400)

def requires_auth(permission=''):
    def requires_auth_decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            token = get_token_auth_header()
            payload = verify_decode_jwt(token)
            check_permissions(permission, payload)
            return f(payload, *args, **kwargs)

        return wrapper
    return requires_auth_decorator