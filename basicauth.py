"""
    This middleware provides HTTP Basic Authentication for users.

    In order to work alongside other authentication schemes and middleware, this middleware only performs
    authentication checks and a login() when basic auth credentials have actually been passed to the request.
    Else it just passes the request on unhindered so that other middleware can decide what to do.

    Should the Django session security module be installed it will keep it informed via set_last_activity.

    Should the Django rest framework be installed, we also provide a simple replacement for it's
    SessionAuthentication class that prevents csrf check failures.
"""

import base64
import binascii
from datetime import datetime

from django.utils.deprecation import MiddlewareMixin

try:
    from rest_framework.authentication import SessionAuthentication as _RestSessionAuthentication
    _HAVE_REST_FRAMEWORK = True
except ImportError:
    _RestSessionAuthentication = None
    _HAVE_REST_FRAMEWORK = False

try:
    from session_security.utils import set_last_activity
    _HAVE_SESSION_AUTH = True
except ImportError:
    set_last_activity = None
    _HAVE_SESSION_AUTH = False


UNAUTHORISED_HTML = """
<html>
<head><title>Basic Authentication Required</title></head>
<body><h1>Authorisation failed for this request. Please provide valid credentials.</h1></body>
</html>
"""

class BasicAuthMiddleware(MiddlewareMixin):

    @staticmethod
    def unauthorisedResponse():
        from django.conf import settings
        from django.http import HttpResponse
        response = HttpResponse(UNAUTHORISED_HTML)
        response['WWW-Authenticate'] = 'Basic realm="%s"' % settings.BASIC_AUTH_REALM
        response.status_code = 401
        return response

    def _extractAuthData(self, request):
        if 'HTTP_AUTHORIZATION' not in request.META:
            # not valid basic auth, ignore request
            return None

        auth = request.META['HTTP_AUTHORIZATION'].split()

        if len(auth) != 2:
            # not valid basic auth, ignore request
            return None

        auth_method, auth_data = auth

        if auth_method.lower() != "basic":
            # not valid basic auth, ignore request
            return None

        return auth_data

    def process_request(self, request):
        from django.contrib.auth import authenticate, login

        if request.user.is_authenticated():
            if _HAVE_SESSION_AUTH:
                set_last_activity(request.session, datetime.now())
            return None

        auth_data = self._extractAuthData(request)
        if not auth_data:
            # not valid basic auth, ignore request
            return None

        try:
            auth_data = base64.b64decode(auth_data)
        except (TypeError, binascii.Error):
            return None

        try:
            auth_data = auth_data.decode('utf-8')
        except UnicodeDecodeError:
            return None

        uname, passwd = base64.b64decode(auth_data).decode().split(':', 1)
        user = authenticate(username=uname, password=passwd)

        if user is not None and user.is_active:
            login(request, user)
            request.user = user
            request._basic_authenticated = True
            return None
        else:
            return self.unauthorisedResponse()


if _HAVE_REST_FRAMEWORK:
    class RestSessionAuthentication(_RestSessionAuthentication):

        def enforce_csrf(self, request):
            if getattr(request, '_basic_authenticated', False):
                # This request was not authenticated by the django session security module,
                # so its CSRF check will fail. Avoid.
                return
            _RestSessionAuthentication.enforce_csrf(self, request)
