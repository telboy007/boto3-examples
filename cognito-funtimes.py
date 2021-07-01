def user_login(username, password):
    """ warrant was a bust we need to do everything ourselves """
    try:
        client = boto3.client("cognito-idp", region_name=config["env_region"])
        response = client.initiate_auth(
            AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters={
                "USERNAME": username,
                "PASSWORD": password
            },
            ClientId=config["admin_client_id"]
        )
        return response
    except Exception as e:
        logger.error("User log-in: %s", e)
        raise


def parse_auth_tokens(result, parse_refresh_token):
    """ parse cognito auth results to flask session """
    try:
        access_token = result["AuthenticationResult"]["AccessToken"]
        id_token = result["AuthenticationResult"]["IdToken"]
        token_type = result["AuthenticationResult"]["TokenType"]
        expires_in = result["AuthenticationResult"]["ExpiresIn"]

        # when we refresh the access token we don't get a refresh token
        if parse_refresh_token:
            refresh_token = result["AuthenticationResult"]["RefreshToken"]
        else:
            refresh_token = session["refresh_token"]

        # update session
        session["access_token"] = access_token
        session["refresh_token"] = refresh_token
        session["id_token"] = id_token
        session["token_type"] = token_type
        session["expires_in"] = expires_in
        session["token_timestamp"] = datetime.now()

        if config["debug"]:
            print(f'Token refreshed {session["token_timestamp"]}')
    except Exception as e:
        logger.error("Parsing auth tokens: %s", e)
        raise


def check_token(session):
    """ warrant was a bust so doing it old school """
    try:
        token_timestamp = session["token_timestamp"]
        refresh_token = session["refresh_token"]

        if config["debug"]:
            print(f'Checking current session...')

        result = check_token_expiry(token_timestamp, False)

        if config["debug"]:
            print(f'Need to renew tokens? {result}')

        if result:
            result = renew_access_token(refresh_token)
            parse_auth_tokens(result, False)

        if config["debug"]:
            print(f'Finished checking session.')
    except Exception as e:
        if config["debug"]:
            print(f'Invalid session: {e}')
        user_logout(session)


def renew_access_token(refresh_token):
    """ warrant is busted so we need to do the heavy lifting """
    try:
        if config["debug"]:
            print("Refreshing token...")
        client = boto3.client("cognito-idp", region_name=config["env_region"])
        response = client.initiate_auth(
            AuthFlow="REFRESH_TOKEN_AUTH",
            AuthParameters={
                "REFRESH_TOKEN": refresh_token
            },
            ClientId=config["admin_client_id"]
        )
        return response
    except Exception as e:
        if config["debug"]:
            print(f'Exception: {e}')
        raise Exception(str(e))


def user_logout(session):
    """ calls warrant logout method and clears session """
    try:
        access_token = session["access_token"]
        if config["debug"]:
            print("Logging out of cognito and clearing current session.")

        client = boto3.client("cognito-idp", region_name=config["env_region"])
        response = client.global_sign_out(
            AccessToken=access_token
        )
        session.clear()
    except Exception as e:
        if config["debug"]:
            print(f'Could not log out of Cognito ({e}), only clearing session.')
        session.clear()


def check_token_expiry(date, aware):
    utc = UTC()
    try:
        if aware:
            delta = datetime.now(utc) - date
        else:
            delta = datetime.now() - date
        result = (delta.days * (24 * 60)) + delta.seconds/3600
        if result > 1:
            return True

        return False
    except Exception as e:
        logger.error("Checking token expiry: %s", e)
        raise
