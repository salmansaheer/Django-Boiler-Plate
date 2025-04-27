from rest_framework_simplejwt.tokens import AccessToken, RefreshToken
from rest_framework_simplejwt.exceptions import TokenError

from utils.request_utils import save_logout_details

class JWTAuthFromCookieMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Retrieve the access token and refresh token from cookies
        access_token = request.COOKIES.get('access_token')
        refresh_token = request.COOKIES.get('refresh_token')
        if access_token:
            try:
                # Verify the access token
                AccessToken(access_token)
                # If valid, set the Authorization header to include the token
                request.META['HTTP_AUTHORIZATION'] = f'Bearer {access_token}'
            except TokenError:
                # If the access token is invalid or expired, check the refresh token
                if refresh_token:
                    try:
                        # Use the refresh token to generate a new access token
                        token = RefreshToken(refresh_token)
                        new_access_token = str(token.access_token)
                        # Set the new access token in the request's Authorization header
                        request.META['HTTP_AUTHORIZATION'] = f'Bearer {new_access_token}'
                        # Store the new access token in request to update the cookies later
                        request._new_access_token = new_access_token
                    except TokenError:
                        # If refresh token is also invalid, flag the cookies for deletion
                        request._delete_cookies = True

        # Proceed to the next middleware or the view
        response = self.get_response(request)

        # After the view is processed, set the new access token if applicable
        if hasattr(request, '_new_access_token'):
            response.set_cookie(
                key='access_token',
                value=request._new_access_token,
                httponly=True,  # Prevent access by JavaScript
            )

        # If tokens are flagged for deletion, remove them from cookies
        if hasattr(request, '_delete_cookies') and request._delete_cookies:
            if refresh_token:
                save_logout_details(refresh_token, 'Refresh Token Expired')
            response.delete_cookie('access_token')
            response.delete_cookie('refresh_token')

        return response
