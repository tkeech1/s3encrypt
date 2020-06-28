import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="s3encrypt",
    version="version='0.0.1'",
    author="tk",
    author_email="",
    description="A package to store encrypted data in S3",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/tkeech1/s3encrypt",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    entry_points={"console_scripts": ["s3encrypt = s3encrypt.__main__:main"]},
    python_requires=">=3.6",
)
