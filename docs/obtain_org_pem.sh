#!/bin/bash

COMPANYNAME=voronenko
curl -o ${COMPANYNAME}.pem "https://${COMPANYNAME}.auth0.com/pem"
openssl x509 -pubkey -noout -in ${COMPANYNAME}.pem > ${COMPANYNAME}.pub
