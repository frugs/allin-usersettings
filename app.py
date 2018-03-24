"""This is the single sign-on app"""

import asyncio
import base64
import gzip
import ssl
import os
import pickle

import aiohttp
import aiohttp.web
import aiohttp_jinja2
import jinja2
import aioauth_client
import aiohttp_session
import pyrebase

from typing import Union
from aiohttp_session.cookie_storage import EncryptedCookieStorage

DEBUG_USE_SELF_SIGNED_KEY = os.getenv('DEBUG_USE_SELF_SIGNED_KEY', "False").casefold() == "true".casefold()

SECRET_KEY = os.getenv('SECRET_KEY')

SSO_LOGIN_URL = os.getenv('SSO_LOGIN_URL')
SSO_LOGOUT_URL = os.getenv('SSO_LOGOUT_URL')
SSO_REFRESH_TOKEN_URL = os.getenv('SSO_REFRESH_TOKEN_URL')

BLIZZARD_CLIENT_KEY = os.getenv("BLIZZARD_CLIENT_KEY")
BLIZZARD_CLIENT_SECRET = os.getenv("BLIZZARD_CLIENT_SECRET")
BLIZZARD_CALLBACK_URL = os.getenv("BLIZZARD_CALLBACK_URL")

DISCORD = aioauth_client.OAuth2Client("", "", base_url='https://discordapp.com/api/v6/')
BOT_TOKEN = os.getenv("BOT_TOKEN")

FIREBASE_CONFIG = os.getenv("FIREBASE_CONFIG")


def blizzard_eu():
    return aioauth_client.OAuth2Client(
        BLIZZARD_CLIENT_KEY,
        BLIZZARD_CLIENT_SECRET,
        base_url="https://eu.api.battle.net/",
        authorize_url="https://eu.battle.net/oauth/authorize",
        access_token_url="https://eu.battle.net/oauth/token")


def blizzard_us():
    return aioauth_client.OAuth2Client(
        BLIZZARD_CLIENT_KEY,
        BLIZZARD_CLIENT_SECRET,
        base_url="https://us.api.battle.net/",
        authorize_url="https://us.battle.net/oauth/authorize",
        access_token_url="https://us.battle.net/oauth/token")


def blizzard_kr():
    return aioauth_client.OAuth2Client(
        BLIZZARD_CLIENT_KEY,
        BLIZZARD_CLIENT_SECRET,
        base_url="https://kr.api.battle.net/",
        authorize_url="https://kr.battle.net/oauth/authorize",
        access_token_url="https://kr.battle.net/oauth/token")


def connect_discord(discord_id: str, member_data: dict, connections: list):
    db = create_db_connection()
    db.child("members").child(discord_id).update({
        "discord_display_name": member_data.get("nick", ""),
        "discord_server_nick": member_data.get("nick", "")
    })

    user_connections = {}

    twitch_connection = next((x for x in connections if x.get("type", "") == "twitch"), {})
    if twitch_connection:
        user_connections["twitch"] = {
            "name": twitch_connection.get("name", ""),
            "id": twitch_connection.get("id", "")
        }

    if user_connections:
        db.child("members").child(discord_id).child("connections").set(user_connections)


def connect_blizzard(discord_id: str, battle_tag: str, eu_chars: list, us_chars: list, kr_chars: list):
    db = create_db_connection()
    db.child("members").child(discord_id).update({
        "battle_tag": battle_tag,
        "caseless_battle_tag": battle_tag.casefold()
    })

    def char_key(char: dict) -> str:
        return char["id"] + "-" + char["realm"] + "-" + char["name"]

    if eu_chars or us_chars or kr_chars:
        db.child("members").child(discord_id).child("characters").update({
            "eu": dict((char_key(char), char) for char in eu_chars),
            "us": dict((char_key(char), char) for char in us_chars),
            "kr": dict((char_key(char), char) for char in kr_chars)
        })


def create_db_connection():
    db_config = pickle.loads(gzip.decompress(base64.b64decode(FIREBASE_CONFIG)))
    return pyrebase.initialize_app(db_config).database()


def fetch_from_db(discord_id: str) -> dict:
    result = {}

    with open("firebase.cfg", "rb") as file:
        db_config = pickle.load(file)

    db = pyrebase.initialize_app(db_config).database()
    data = db.child("members").child(discord_id).get().val()

    if data:
        if "battle_tag" in data:
            result["battle_tag"] = data["battle_tag"]
        if "characters" in data:
            result["characters"] = {}
            for key, value in data["characters"].items():
                result["characters"][key] = list(value.values())
        if "connections" in data:
            result["connections"] = data["connections"]

    return result


def discord_auth_headers(access_token: str) -> dict:
    return {'Authorization': "Bearer " + access_token}


async def refresh_discord_token(session: dict) -> str:
    refresh_token_response = await aiohttp.request(
        "POST",
        SSO_REFRESH_TOKEN_URL,
        json={"discord_refresh_token": session.get("discord_refresh_token", "")})

    if refresh_token_response.status == 200:
        refresh_token_data = await refresh_token_response.json()
        access_token = refresh_token_data['access_token']
        session['discord_refresh_token'] = refresh_token_data['refresh_token']
        return access_token
    else:
        return ""


async def root(_: aiohttp.web.Request) -> aiohttp.web.Response:
    return aiohttp.web.HTTPMovedPermanently('index')


@aiohttp_jinja2.template('index.html.j2')
async def index(request: aiohttp.web.Request) -> Union[dict, aiohttp.web.Response]:
    """This is the main landing page for the app"""
    session = await aiohttp_session.get_session(request)
    access_token = await refresh_discord_token(session)

    if access_token:
        resp = await DISCORD.request('GET', 'users/@me', headers=discord_auth_headers(access_token))
        if resp.status == 200:
            discord_data = await resp.json()

            discord_id = discord_data['id']
            discord_avatar = "https://cdn.discordapp.com/avatars/{}/{}".format(discord_id, discord_data['avatar'])

            resp2 = await DISCORD.request(
                'GET',
                'guilds/154861527906779136/members/' + discord_id,
                headers={'Authorization': 'Bot ' + BOT_TOKEN})
            if resp2.status == 200:
                member_data = await resp2.json()
            else:
                return aiohttp.web.HTTPFound(SSO_LOGOUT_URL)

            resp3 = await DISCORD.request('GET', 'users/@me/connections', headers = discord_auth_headers(access_token))
            connections = (await resp3.json()) if resp3.status == 200 else []

            await asyncio.get_event_loop().run_in_executor(
                None, connect_discord, discord_id, member_data, connections)

            db_data = await asyncio.get_event_loop().run_in_executor(None, fetch_from_db, discord_id)

            is_blizzard_account_connected = "battle_tag" in db_data and "characters" in db_data
            twitch_connection = db_data.get("connections", {}).get("twitch", {})
            is_twitch_account_connected = bool(twitch_connection.get("name", ""))

            return {
                "username": discord_data['username'],
                "discord_avatar": discord_avatar,
                "sign_out_url": SSO_LOGOUT_URL,
                "is_blizzard_account_connected": is_blizzard_account_connected,
                "is_twitch_account_connected": is_twitch_account_connected,
                "battle_tag": db_data.get("battle_tag", ""),
                "eu_characters": db_data.get("characters", {}).get("eu", []),
                "us_characters": db_data.get("characters", {}).get("us", []),
                "kr_characters": db_data.get("characters", {}).get("kr", []),
                "twitch_connection": twitch_connection,
            }

    return aiohttp.web.HTTPFound(SSO_LOGIN_URL)


async def blizzard_login(_: aiohttp.web.Request) -> aiohttp.web.Response:
    """This is the endpoint to direct the client to start the oauth2 dance for the Blizzard API"""
    params = {
        'scope': 'sc2.profile',
        'response_type': 'code',
        'redirect_uri': BLIZZARD_CALLBACK_URL,
    }
    url = blizzard_us().get_authorize_url(**params)
    return aiohttp.web.HTTPFound(url)


async def blizzard_authorised(request: aiohttp.web.Request) -> aiohttp.web.Response:
    """This is the endpoint for the oauth2 callback for the Blizzard API"""
    code = request.rel_url.query.get('code')
    if code is None:
        return aiohttp.web.HTTPFound('index')

    session = await aiohttp_session.get_session(request)
    discord_token = await refresh_discord_token(session)

    if not discord_token:
        return aiohttp.web.HTTPFound('index')

    discord_resp = await DISCORD.request('GET', 'users/@me', headers=discord_auth_headers(discord_token))
    if discord_resp.status != 200:
        return aiohttp.web.HTTPFound('index')

    discord_data = await discord_resp.json()
    discord_id = discord_data["id"]

    blizzard_eu_client = blizzard_eu()
    blizzard_us_client = blizzard_us()
    blizzard_kr_client = blizzard_kr()

    blizzard_token, _ = await blizzard_us_client.get_access_token(code, redirect_uri=BLIZZARD_CALLBACK_URL)
    blizzard_eu_client.access_token = blizzard_token
    blizzard_kr_client.access_token = blizzard_token

    user_resp = await blizzard_us_client.request("GET", "account/user")
    if discord_resp.status != 200:
        return aiohttp.web.HTTPFound('index')

    user_data = await user_resp.json()
    battle_tag = user_data.get("battletag", "")

    if not battle_tag:
        return aiohttp.web.HTTPFound('index')

    def extract_character_data(character: dict):
        return {
            "name": character.get("displayName", ""),
            "clan": character.get("clanName", ""),
            "id": str(character.get("id", 0)),
            "realm": str(character.get("realm", 1)),
            "profile_path": character.get("profilePath", ""),
            "avatar": character.get("avatar", {}).get("url", "")
        }

    eu_characters = []
    us_characters = []
    kr_characters = []
    
    eu_profile_resp = await blizzard_eu_client.request("GET", "sc2/profile/user")
    if eu_profile_resp.status == 200:
        eu_profile_data = await eu_profile_resp.json()
        eu_characters.extend([
            extract_character_data(character)
            for character
            in eu_profile_data.get("characters", [])
        ])

    us_profile_resp = await blizzard_us_client.request("GET", "sc2/profile/user")
    if us_profile_resp.status == 200:
        us_profile_data = await us_profile_resp.json()
        us_characters.extend([
            extract_character_data(character)
            for character
            in us_profile_data.get("characters", [])
        ])

    kr_profile_resp = await blizzard_kr_client.request("GET", "sc2/profile/user")
    if kr_profile_resp.status == 200:
        kr_profile_data = await kr_profile_resp.json()
        kr_characters.extend([
            extract_character_data(character)
            for character
            in kr_profile_data.get("characters", [])
        ])

    await asyncio.get_event_loop().run_in_executor(
        None,
        connect_blizzard,
        discord_id,
        battle_tag,
        eu_characters,
        us_characters,
        kr_characters)

    return aiohttp.web.HTTPFound("index")


def main():
    app = aiohttp.web.Application()
    aiohttp_jinja2.setup(app, loader=jinja2.FileSystemLoader('templates/'))
    aiohttp_session.setup(app, EncryptedCookieStorage(SECRET_KEY, max_age=604800))

    app.router.add_static('/static/', 'static/')
    app.router.add_get('/', root)
    app.router.add_get('/index', index)
    app.router.add_get('/blizzard-login', blizzard_login)
    app.router.add_get('/blizzard-authorised', blizzard_authorised)

    if DEBUG_USE_SELF_SIGNED_KEY:
        sslcontext = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
        sslcontext.load_cert_chain('cert.pem', 'key.pem')
    else:
        sslcontext = None

    aiohttp.web.run_app(app, port=5001, ssl_context=sslcontext)


if __name__ == "__main__":
    main()
