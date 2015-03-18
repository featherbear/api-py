import requests
import json


oauth_url = "https://api.elvanto.com/oauth"
token_url = "https://api.elvanto.com/oauth/token"
api_url = "https://api.elvanto.com/v1/"


def _AuthorizeURL(client_id, redirect_uri, scope, WebOrNon, state=None):
    """
    Function to gain the URL needed for users to log in to your integration.
    Web Apps and Non Web Apps both use this function, it simply returns a different URL
    Non Web Apps don't use the state argument
    :param client_id: Int - The Client ID of your integration
    :param redirect_uri: Str - The URL to redirect users to after they have logged on
    :param scope: List or Str - Scope the Web App requires to function
    :param state: Optional Argument, only use if needed in your redirection call
    :param WebOrNon: Str - WebApp or NonWebApp. Web Apps and Non WebApps have different URLs they send users to
    :return: Returns a string representing the URL for users of your Web App to log inwith
    """
    if type(scope) == list:
        newscope = ""
        for item in scope:
            newscope += item + ","
        newscope = newscope[:-1] #Trimming the final comma
    else:
        newscope = scope
    if WebOrNon == "WebApp":
        if state:
            info = {
                "id":str(client_id),
                "uri": redirect_uri,
                "scope": newscope,
                "state": state
            }
            return oauth_url + "?type=web_server&client_id={id}&redirect_uri={uri}&scope={scope}&state={state}".format(**info)
        else:
            info = {
                "id": str(client_id),
                "uri": redirect_uri,
                "scope": newscope
            }
            return oauth_url + "?type=web_server&client_id={id}&redirect_uri={uri}&scope={scope}".format(**info)
    elif WebOrNon == "NonWebApp":
        info = {
            "id":str(client_id),
            "uri": redirect_uri,
            "scope": newscope
        }
        return oauth_url + "?type=user_agent&client_id={id}&redirect_uri={uri}&scope={scope}".format(**info)


def _GetTokens(client_id, client_secret, code, redirect_uri):
    """
    Gets the acccess tokens, after the user has logged into the Web App via URL provided in the getURL function
    :param client_id: Int - Client ID of your integration
    :param client_secret: Str - Client Secret of your integration
    :param code: Int - The Code returned after user logs in
    :param redirect_uri: Str - The redirect_uri specified in getURL
    :return: Dict object, in the form {"access_token":string,"expires_in":int,"refresh_token":string}
    """
    global token_url
    info = {
        "client_id": client_id,
        "client_secret": client_secret,
        "code": code,
        "redirect_uri": redirect_uri
    }
    params = "grant_type=authorization_code&client_id={client_id}&client_secret={client_secret}&code={code}&redirect_uri={redirect_uri}".format(**info)
    headers = {
        "Content-Type":"application/x-www-form-urlencoded"
    }
    data = requests.post(token_url, data=params, headers=headers)
    string = data.text.decode('UTF-8')
    return json.loads(string)
    

class Connection():
    def __init__(self, **auth):
        """
        Basic Connection Object.
        To automatically refresh tokens, you need to provide the client_id client_secret and redirect_uri needed for the
        _GetTokens function.
        :param auth: For API Key Authentication; APIKey = String
        :param auth: For Oauth Authentication; AccessToken = String
        :param auth: To enable Token Refresh for Oauth, RefreshToken = Str
        """
        self.s = requests.Session() #This is the object class that is used to do the calls.
        if "APIKey" in auth:
            self.s.auth = (auth["APIKey"],"") #Auth Header is a Tuple, of Username,Password. No Password needed so left blank
        elif "AccessToken" in auth:
            self.s.headers = {
                'Authorization':'Bearer %s' % auth["AccessToken"]
            } #Authorization header
            if "RefreshToken" in auth:
                self.refresh_token = auth["RefreshToken"]
            else:
                self.refresh_token = None

        else: #If not either of these, invalid Auth. Raise Syntax Error
            raise SyntaxError("Invalid Auth. Please use APIKey=String or AccessToken=String, ExpiresIn=Float")


    def _RefreshToken(self):
        """
        Function to refresh the tokens.
        :param time: Optional argument. Set to true if you want to return the new expires_in value
        :return: Nothing if time==False, Unix timestamp if time==true
        """
        global token_url
        headers = {
            "Content-Type":"application/x-www-form-urlencoded"
        }
        params = "grant_type=refresh_token&refresh_token={refresh_token}".format(self.refresh_token)
        data = requests.post(url, data=params, headers=headers)
        string = data.text.decode('UTF-8')
        new_tokens = json.loads(string)
        self.refresh_token = new_tokens["refresh_token"]
        return



    def _Post(self, endpoint, **kwargs): #API Endpoint, Arguements -> json File
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
        if endpoint[:-1] == ".":
            posturl = api_url + endpoint + "json"
        else:
            posturl = api_url + endpoint + ".json"

        self.data = self.s.post(posturl, json=kwargs) #This is the code that does the actual call.
        string=self.data.text.decode('UTF-8') #Decoding the response to be something python will like
        info = json.loads(string)
        if info["status"] != "ok":
            if int(info["error"]["code"]) == 121: #Token Expired
                if self.refresh_token: #Can't refresh if no refresh token
                    self._RefreshToken() #Refresh Tokens
                    info = self._Post(endpoint, **kwargs) #Make call again
                else:
                    return {
                        "status":"Token expired please renew"
                    }
        return info

