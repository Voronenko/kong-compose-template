FROM kong:2.0.2-ubuntu
LABEL description="Ubuntu + Kong 2.0.2 + kong-oidc plugin"
RUN apt update -y && apt install -y git unzip luarocks && apt-get -y clean
RUN luarocks install kong-oidc
RUN luarocks install kong-plugin-sa-jwt-claims-validate
