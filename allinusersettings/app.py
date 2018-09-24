"""This is the single sign-on app"""
import json
import os

import allinsso
import flask
import flask_oauthlib.client
import pyrebase
import requests
import base64

from google.cloud import datastore


def retrieve_config_value(key: str) -> str:
    datastore_client = datastore.Client()
    return datastore_client.get(datastore_client.key("Config", key))["value"]


DEBUG = os.getenv("DEBUG", "false").casefold() == "true".casefold()
SECRET_KEY = retrieve_config_value("cookieEncryptionKey")
DISCORD_CLIENT_KEY = retrieve_config_value("discordClientKey")
DISCORD_CLIENT_SECRET = retrieve_config_value("discordClientSecret")
BLIZZARD_CLIENT_KEY = os.getenv("BLIZZARD_CLIENT_KEY") if DEBUG else retrieve_config_value(
    "blizzardClientKey")
BLIZZARD_CLIENT_SECRET = os.getenv("BLIZZARD_CLIENT_SECRET") if DEBUG else retrieve_config_value(
    "blizzardClientSecret")
BOT_TOKEN = retrieve_config_value("discordBotToken")
FIREBASE_CONFIG = json.loads(retrieve_config_value("firebaseConfig"))
SSO_REFRESH_TOKEN_URL = "sso/discord-refresh-token"
SSO_LOGIN_URL = "/sso/"
SSO_LOGOUT_URL = "/sso/discord-signout"

app = flask.Flask(__name__)
app.secret_key = SECRET_KEY
app.config["SESSION_COOKIE_HTTPONLY"] = True

oauth = flask_oauthlib.client.OAuth(app)

discord = allinsso.create_discord_remote_app(oauth, DISCORD_CLIENT_KEY, DISCORD_CLIENT_SECRET)


def blizzard_oauth(region: str) -> flask_oauthlib.client.OAuthRemoteApp:
    return oauth.remote_app(
        "blizzard_{}".format(region),
        request_token_params={"scope": "sc2.profile"},
        consumer_key=BLIZZARD_CLIENT_KEY,
        consumer_secret=BLIZZARD_CLIENT_SECRET,
        base_url="https://{}.api.battle.net/".format(region),
        authorize_url="https://{}.battle.net/oauth/authorize".format(region),
        access_token_url="https://{}.battle.net/oauth/token".format(region),
        access_token_method='POST',
        access_token_headers={
            "User-Agent":
                "Mozilla/5.0",
            "Authorization":
                "Basic " + base64.b64encode("{}:{}".format(
                    BLIZZARD_CLIENT_KEY, BLIZZARD_CLIENT_SECRET).encode()).decode()
        },
        access_token_params={"scope": "sc2.profile"},
    )


blizzard_eu = blizzard_oauth("eu")
blizzard_us = blizzard_oauth("us")
blizzard_kr = blizzard_oauth("kr")


def connect_discord(discord_id: str, member_data: dict, connections: list):
    db = create_db_connection()
    db.child("members").child(discord_id).update({
        "discord_display_name": member_data.get("nick", ""),
        "discord_server_nick": member_data.get("nick", ""),
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


def connect_blizzard(discord_id: str, battle_tag: str, eu_chars: list, us_chars: list,
                     kr_chars: list):
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
    return pyrebase.initialize_app(FIREBASE_CONFIG).database()


def fetch_from_db(discord_id: str) -> dict:
    result = {}

    db = create_db_connection()
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
    return {'Authorization': "Bearer " + access_token, "User-Agent": "Mozilla/5.0"}


@app.route("/")
def index():
    """This is the main landing page for the app"""

    access_token = allinsso.refresh_discord_token(discord, flask.session)

    if not access_token:
        return flask.redirect(SSO_LOGIN_URL)

    resp = discord.get("users/@me", headers=discord_auth_headers(access_token), token=access_token)
    if resp.status != 200 or not resp.data or "id" not in resp.data:
        return flask.redirect(SSO_LOGIN_URL)

    discord_data = resp.data
    discord_id = discord_data["id"]

    if "avatar" in resp.data:
        discord_avatar = "https://cdn.discordapp.com/avatars/{}/{}".format(
            discord_id, discord_data['avatar'])
    else:
        discord_avatar = ""

    resp2 = requests.get(
        discord.base_url + 'guilds/154861527906779136/members/' + discord_id,
        headers={
            'Authorization': 'Bot ' + BOT_TOKEN
        })

    if resp2.status_code != 200:
        return flask.redirect(SSO_LOGOUT_URL)

    member_data = resp2.json()

    resp3 = discord.get(
        'users/@me/connections', headers=discord_auth_headers(access_token), token=access_token)
    connections = resp3.data if resp3.status == 200 else []

    connect_discord(discord_id, member_data, connections)

    db_data = fetch_from_db(discord_id)

    is_blizzard_account_connected = "battle_tag" in db_data and "characters" in db_data
    twitch_connection = db_data.get("connections", {}).get("twitch", {})
    is_twitch_account_connected = bool(twitch_connection.get("name", ""))

    return flask.render_template(
        "index.html.j2", **{
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
        })


@app.route("/blizzard-login")
def blizzard_login():
    """This is the endpoint to direct the client to start the oauth2 dance for the Blizzard API"""

    return blizzard_us.authorize(
        callback=flask.url_for(blizzard_authorised.__name__, _external=True, _scheme="https"))


@app.route("/blizzard-authorised")
def blizzard_authorised():
    """This is the endpoint for the oauth2 callback for the Blizzard API"""

    blizzard_resp_data = blizzard_us.authorized_response()
    if not blizzard_resp_data or "access_token" not in blizzard_resp_data is None:
        return "Login failed", 401

    blizzard_access_token = blizzard_resp_data["access_token"]

    discord_access_token = allinsso.refresh_discord_token(discord, flask.session)

    if not discord_access_token:
        return flask.redirect(flask.url_for(index.__name__))

    discord_resp = discord.get(
        "users/@me", headers=discord_auth_headers(discord_access_token), token=discord_access_token)
    if discord_resp.status != 200 or "id" not in discord_resp.data:
        return flask.redirect(flask.url_for(index.__name__))

    discord_data = discord_resp.data
    discord_id = discord_data["id"]

    user_resp = blizzard_us.get("account/user", token=blizzard_access_token)
    if user_resp.status != 200 or not user_resp.data or not user_resp.data.get("battletag", ""):
        return flask.redirect(flask.url_for(index.__name__))

    user_data = user_resp.data
    battle_tag = user_data["battletag"]

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

    eu_profile_resp = blizzard_eu.get("sc2/profile/user", token=blizzard_access_token)
    if eu_profile_resp.status == 200 and eu_profile_resp.data:
        eu_profile_data = eu_profile_resp.data
        eu_characters.extend([
            extract_character_data(character)
            for character in eu_profile_data.get("characters", [])
        ])

    us_profile_resp = blizzard_us.get("sc2/profile/user", token=blizzard_access_token)
    if us_profile_resp.status == 200 and us_profile_resp.data:
        us_characters.extend([
            extract_character_data(character)
            for character in us_profile_resp.data.get("characters", [])
        ])

    kr_profile_resp = blizzard_kr.get("sc2/profile/krer", token=blizzard_access_token)
    if kr_profile_resp.status == 200 and kr_profile_resp.data:
        kr_characters.extend([
            extract_character_data(character)
            for character in kr_profile_resp.data.get("characters", [])
        ])

    connect_blizzard(discord_id, battle_tag, eu_characters, us_characters, kr_characters)

    return flask.redirect(flask.url_for(index.__name__))
