import json
import requests

oauth_url = 'https://api.elvanto.com/OAuth'
token_url = 'https://api.elvanto.com/OAuth/token'
api_url = 'https://api.elvanto.com/v1/'


def _AuthorizeURL(ClientID, RedirectURI, Scope, IsWebApp, State=None):
    """
    Function to gain the URL needed for users to log in to your integration.
    Web Apps and Non Web Apps both use this function, it simply returns a different URL
    Non Web Apps don't use the state argument
    :param ClientID: int - The Client ID of your integration
    :param RedirectURI: str - The URL to redirect users to after they have logged on
    :param Scope: list or str - Scope the Web App requires to function
    :param State: (optional) str - Only use if needed in your redirection call
    :param IsWebApp: bool - Web Apps and Non WebApps have different URLs they send users to
    :return: str - Application authorization url
    """
    if type(Scope) == list:  # Convert list to comma delimited string
        Scope = ','.join(Scope)
    info = {
        'id': str(ClientID),
        'uri': RedirectURI,
        'scope': Scope
    }
    if IsWebApp:
        return oauth_url + '?type=web_server&client_id={id}&redirect_uri={uri}&scope={scope}'.format(**info) + (('&state=' + State) if State else '')
    else:
        return oauth_url + '?type=user_agent&client_id={id}&redirect_uri={uri}&scope={scope}'.format(**info)


def _GetTokens(ClientID, ClientSecret, Code, RedirectURI):
    """
    Gets the acccess tokens, after the user has logged into the Web App via URL provided in the getURL function
    :param ClientID: int - Client ID of your integration
    :param ClientSecret: str - Client Secret of your integration
    :param Code: int - The Code returned after user logs in
    :param RedirectURI: str - The redirect_uri specified in getURL
    :return: dict - {"access_token": str, "expires_in": int, "refresh_token": str}
    """
    global token_url
    info = {
        'client_id': ClientID,
        'client_secret': ClientSecret,
        'code': Code,
        'redirect_uri': RedirectURI
    }
    params = 'grant_type=authorization_code&client_id={client_id}&client_secret={client_secret}&code={code}&redirect_uri={redirect_uri}'.format(**info)
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    data = requests.post(token_url, data=params, headers=headers)
    return json.loads(data.text)


class Connection():
    def __init__(self, **auth):
        """
        Basic Connection Object.
        To automatically refresh tokens, you need to provide the client_id client_secret and redirect_uri needed for the _GetTokens function.
        :param auth: For API Key Authentication; APIKey = str
        :param auth: For OAuth Authentication; AccessToken = str
        :param auth: To enable Token Refresh for OAuth, RefreshToken = str
        """
        self.s = requests.Session()
        if 'APIKey' in auth:
            self.API_Key = requests.auth.HTTPBasicAuth(auth['APIKey'], '')

        elif 'AccessToken' in auth:
            self.OAuth = {
                'Authorization': 'Bearer %s' % auth['AccessToken']
            }
            self.refresh_token = auth['RefreshToken'] if 'RefreshToken' in auth else None

        else:  # If neither of these, invalid Auth. Raise Syntax Error
            raise SyntaxError('Invalid Auth method. Please use APIKey (string) or AccessToken (string), ExpiresIn (float)')

    def _RefreshToken(self):
        """
        Function to refresh the tokens.
        :return: int - Expiry time in seconds
        """
        global token_url
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        params = 'grant_type=refresh_token&refresh_token=' + self.refresh_token
        data = requests.post(token_url, data=params, headers=headers)
        new_tokens = json.loads(data.text)
        self.__init__(AccessToken=new_tokens['access_token'], RefreshToken=new_tokens['refresh_token'])
        return new_tokens['expires_in']

    def _Post(self, endpoint, **kwargs):
        """
        How the wrapper does the API Calls.
        :param endpoint: Endpoint of the API Call. Ie people/getInfo
        :param kwargs: Arguments for the call. Simple arguments can be Arg=Value.
        Arguments like 'Fields' or 'Search' are more complex and need to be formatted as:
            fields=[mobile,family]
            search={'mobile':number}
        :return: Returns a Dict that corresponds to the JSON for the API call.
        """
        global api_url
        posturl = api_url + endpoint + ('' if endpoint[:-1] == '.' else '.') + 'json'

        if self.API_Key:
            self.data = requests.post(posturl, auth=self.API_Key, json=kwargs)
        elif self.OAuth:
            self.data = requests.post(posturl, headers=self.OAuth, json=kwargs)
        info = json.loads(self.data.text)
        if info['status'] != 'ok':
            if int(info['error']['code']) == 121:  # Token Expired
                if self.refresh_token:  # Can't refresh if no refresh token
                    self._RefreshToken()  # Refresh Tokens
                    info = self._Post(endpoint, **kwargs)  # Make call again
                else:
                    return {
                        'status': 'Token expired please renew'
                    }
        return info
