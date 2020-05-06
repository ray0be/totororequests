import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="totororequests",
    version="1.1.2",
    author="Victor Paynat-Sautivet",
    author_email="contact@ray0.be",
    description="Smart Python module for sending HTTP(S) requests through Tor network",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/ray0be/totororequests",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: Unix",
    ],
    python_requires='>=3.6',
)