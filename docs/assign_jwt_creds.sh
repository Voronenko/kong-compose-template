#!/bin/bash

COMPANYNAME=voronenko
CONSUMERNAME=auth0voronenko
curl -i -X POST http://localhost:8001/consumers/${CONSUMERNAME}/jwt \
    -F "algorithm=RS256" \
    -F "rsa_public_key=@./${COMPANYNAME}.pub" \
    -F "key=https://${COMPANYNAME}.auth0.com/"
