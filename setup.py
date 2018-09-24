import setuptools

VERSION = "0.0.2"

setuptools.setup(
    name="allinusersettings",
    packages=setuptools.find_packages(),
    package_data={"allinusersettings": ["templates/*", "static/styles/*", "static/images/*"]},
    version=VERSION,
    description="User Settings app for All Inspiration Apps",
    author="Hugo Wainwright",
    author_email="wainwrighthugo@gmail.com",
    url="https://github.com/frugs/allin-usersettings",
    keywords=["sc2", "all-inspiration"],
    classifiers=[],
    install_requires=[
        "requests>=2.19.1",
        "requests-toolbelt>=0.8.0",
        "Flask-OAuthlib",
        "flask",
        "pyrebase",
        "google-cloud-datastore",
        "allinsso",
    ],
)
