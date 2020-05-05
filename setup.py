from setuptools import setup, find_packages


requirements = ['requests', 'requests_oauthlib']

setup(
    name="oauth-cli",
    version="0.1.0",
    description="Simple python cli to obtain oauth tokens.",
    author="Jonathan Villemaire-Krajden",
    author_email="jonathan@j-vk.com",
    install_requires=requirements,
    python_requires=">=3.6",
    classifiers=[
        "License :: OSI Approved :: MIT",
        "Programming Language :: Python :: 3",
    ],
)
