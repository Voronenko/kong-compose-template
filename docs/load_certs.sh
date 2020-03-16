#!/bin/bash

KONG="http://localhost:8001"
SNIS="*.lvh.voronenko.net"

set -xe

curl -i -X POST $KONG/certificates \
    -F "cert=@./certs/fullchain.pem" \
    -F "key=@./certs/privkey.pem" \
    -F "snis[]=*.lvh.voronenko.net" \
    -F "tags[]=default" \
    -F "tags[]=lvh"
