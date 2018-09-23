import werkzeug.wrappers
from werkzeug.serving import run_simple
from werkzeug.wsgi import DispatcherMiddleware

from allinusersettings import app as usersettings_app
from allinsso import app as sso_app


def main():
    run_simple(
        "localhost",
        5000,
        DispatcherMiddleware(
            werkzeug.wrappers.Response("Nothing to see here!", status=404), {
                "/sso": sso_app,
                "/usersettings": usersettings_app
            }),
        threaded=True)


if __name__ == "__main__":
    main()
