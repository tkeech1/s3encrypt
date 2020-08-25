FROM python:3.8-buster
#FROM ubuntu:focal

ARG USERNAME=python
# On Linux, replace with your actual UID, GID if not the default 1000
ARG USER_UID=1000
ARG USER_GID=$USER_UID

# Create the user
RUN groupadd --gid $USER_GID $USERNAME \
    && useradd --uid $USER_UID --gid $USER_GID -m $USERNAME \
    && mkdir -p /home/$USERNAME/.vscode-server /home/$USERNAME/.vscode-server-insiders \
    && chown ${USER_UID}:${USER_GID} /home/$USERNAME/.vscode-server*

# ********************************************************
# * Anything else you want to do like clean up goes here *
# ********************************************************

# dependencies for pyenv
RUN apt-get update && apt-get install -y git make build-essential libssl-dev zlib1g-dev libbz2-dev libreadline-dev libsqlite3-dev wget curl llvm libncurses5-dev libncursesw5-dev xz-utils tk-dev libffi-dev liblzma-dev python-openssl && rm -rf /var/lib/apt/lists/*

# change the username
USER $USERNAME

# install pyenv 
RUN curl https://pyenv.run | bash

RUN pip install pipenv tox tox-pyenv --upgrade --user

ENV PATH="${PATH}:/home/${USERNAME}/.local/bin:/home/${USERNAME}/.pyenv/bin"

# setup pyenv
RUN echo 'eval "$(pyenv init -)"' >> /home/${USERNAME}/.bashrc
RUN echo 'eval "$(pyenv virtualenv-init -)"' >> /home/${USERNAME}/.bashrc

RUN pyenv update && pyenv install -v 3.7.0
RUN pyenv update && pyenv install -v 3.8.0

ENV PYENV_ROOT="/home/${USERNAME}/.pyenv"
ENV PIPENV_PYTHON="${PYENV_ROOT}/shims/python"
