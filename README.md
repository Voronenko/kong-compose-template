# How to use this template

This Docker Compose template provisions a Kong container with a Postgres database, plus a nginx load-balancer. After running the template, the `nginx-lb` load-balancer will be the entrypoint to Kong.

To run this template execute:

```shell
$ docker-compose up
```

To scale Kong (ie, to three instances) execute:

```shell
$ docker-compose scale kong=3
```

Kong will be available through the `nginx-lb` instance on port `8000`, and `8001`. You can customize the template with your own environment variables or datastore configuration.

Kong's documentation can be found at [https://docs.konghq.com/][kong-docs-url].

Additionally, compose file contains kong ui, sa called konga https://github.com/pantsel/konga,  available at port 1337

For Konga you can use some admin name (kind of Slavko / KongaKong) with unique connection name kongakompose and admin endpoint
http://kong:8001/

# Integrating with Auth0

## Web application (interactive login via browser UI)

This flow supposes, that API accessible through kong will be consumed by some browser application, while user management and authorization is delegated to some
third party service, in our case Auth0. To accomplish this, one of the Nokia teams implemented plugin `kong-oidc` available at https://github.com/nokia/kong-oidc.
This plugin should be preinstalled on a kong machine and activated.

In our example we use docker, thus we will use slightly modified kong image:

```
FROM kong:1.4.0-ubuntu
LABEL description="Ubuntu + Kong 1.4.0 + kong-oidc plugin"
RUN luarocks install kong-oidc
```

On Auth0 interface lets create SPA application.

![alt](docs/00_auth0_spa_app.png)

For further ideas, check advanced settings, and ensure that you can add up to 10 255 byte long custom value pairs, that will be later passed to your api behind kong.

Also recall that, there is Rules section,  where you can implement number of javascript
routines with custom logic, that may add number of realtime parameters to the request passed.

```js
function (user, context, callback) {

  context.idToken.yourcustomattrs = ['someattr1', 'someattr2'];
  return callback(null, user, context);
}
```

In that scenario you will have some web application running at some domain.  Let's assume,
it is http://app.lvh.voronenko.net/  - it has some custom portal logic, but also consumes data from microservices hosted behind kong, running at endpoint  http://app.lvh.voronenko.net:8000/

Lets mock it:

Create the service

```sh

curl -i -X POST \
--url {{ kong }}/services/ \
--data 'name={{ spaservice_name }}' \
--data 'url=https://httpbin.org/get'

HTTP/1.1 201 Created

```

Create route, service will be exposed at {{ domain }}/spa/

```sh

curl -i -X POST \
--url {{ kong }}/services/{{ spaservice_name }}/routes \
--data 'hosts[]={{domain}}&paths[]=/spa/'
```

If everything ok, you should get at /spa/ endpoint copy of the enchanced
request received.

```
HTTP/1.1 200 OK
...
Via: kong/1.4.0

{
  "args": {},
  "headers": {
    "Accept-Encoding": "gzip, deflate",
    "Host": "httpbin.org",
    "User-Agent": "vscode-restclient",
    "X-Forwarded-Host": "app.lvh.voronenko.net"
  },
  "origin": "172.20.0.1, 172.20.0.1",
  "url": "https://app.lvh.voronenko.net/get"
}
```

Now lets protect our endpoind with auth0 authentication.
We will need to get three additional parameters:

```
# Can be obtained at application settings page
@spa_client_id=Duz71pNGTg8RH7hwy0nrqy1DUGXyr2sy
@spa_client_secret=w06r1bAyufGszfdpicRGerNJ9g2bTC2abV0j-9ihgHqPNGd3Gs-ua0-lRGyGKfnb
# discovery url is fixed
@spa_discovery=https://{{ companyname }}.auth0.com/.well-known/openid-configuration
```

Let's associate plugin with the service

```
curl -i -X POST \
--url {{ kong }}/services/{{ spaservice_name }}/plugins \
--data 'name=oidc&&config.client_id={{ spa_client_id }}&config.client_secret={{ spa_client_secret }}&config.discovery={{ spa_discovery }}'
```

If you check documentations of the plugins, you will note that it has number of customizations, that allows to redirect to proper pages of your main portal after login and so on.

![alt](docs/03_oidc_service.png)

Additionally, we need to inform auth0 about callbacks used. If your application
does not have own, kong can provide default ones, which would reside under
`/cb`

![alt](docs/04_allowed_callback_urls.png)

Now, if you would try to navigate to `{{ domain_endpoint }}/spa/`, you will get
redirected to auth0, where you can login with credentials given, including social logins.

![alt](docs/05_auth0_login_ui.png)

Upon successful login we are redirected back to kong, and now

```
{
  "args": {},
  "headers": {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3",
    "Accept-Encoding": "gzip, deflate", 
    "Accept-Language": "en-US,en;q=0.9,ru-UA;q=0.8,ru;q=0.7,uk;q=0.6",
    "Cookie": "session=UHH45jCV9A87Aev2IEBCJA..|1575582049|4Kc2 ... .",
    "Dnt": "1",
    "Host": "httpbin.org",
    "Upgrade-Insecure-Requests": "1",
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.108 Safari/537.36",
    "X-Forwarded-Host": "app.lvh.voronenko.net",
    "X-Userinfo": "eyJuaWNrbmFtZSI6ImF2aXNiaXJkIiwiaWQiOiJnb29nbGUtb2F1dGgyfDEwMjE2MTg5MzYxMDUxMzg5MDczMyIsImxvY2FsZSI6ImVuIiwibmFtZSI6IlZ5YWNoZXNsYXYgViIsImVtYWlsIjoiYXZpc2JpcmRAZ21haWwuY29tIiwiZ2l2ZW5fbmFtZSI6IlZ5YWNoZXNsYXYiLCJ1cGRhdGVkX2F0IjoiMjAxOS0xMi0wNVQyMDo1NToyMS4wNThaIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsInBpY3R1cmUiOiJodHRwczpcL1wvbGg0Lmdvb2dsZXVzZXJjb250ZW50LmNvbVwvLXo0am1QaFZKTDE4XC9BQUFBQUFBQUFBSVwvQUFBQUFBQUFBQUFcL0FDSGkzcmQ2R1FqZXdQV3Zra2RRVmJ5WGF1QlZCbE0tUVFcL3Bob3RvLmpwZyIsInN1YiI6Imdvb2dsZS1vYXV0aDJ8MTAyMTYxODkzNjEwNTEzODkwNzMzIiwiZmFtaWx5X25hbWUiOiJWIn0="
  },
  "origin": "172.20.0.1, 172.20.0.1",
  "url": "https://app.lvh.voronenko.net/get"
}
```

As we see, now user is authorized to use or API in kong, and `oidc` plugin
also adds special header called `X-Userinfo`, which contains base64 encoded jwt token. At the same moment, plugin performs validation of the token signature, and also can be configured to do more background checks.

You can use https://jwt.io/ to view token insides

```
{
  "nickname": "avisbird",
  "id": "google-oauth2|102161893610513890733",
  "locale": "en",
  "name": "Vyacheslav V",
  "email": "someemail",
  "given_name": "Vyacheslav",
  "updated_at": "2019-12-05T20:55:21.058Z",
  "email_verified": true,
  "picture": "https://lh4.googleusercontent.com/-z4jmPhVJL18/AAAAAAAAAAI/AAAAAAAAAAA/ACHi3rd6GQjewPWvkkdQVbyXauBVBlM-QQ/photo.jpg",
  "sub": "google-oauth2|102161893610513890733",
  "family_name": "V"
}
```

And the same information can be now extracted by next plugin in chain or 
end service.

Note, that there is some mess with rules and hooks, as discussed in that thread
https://community.auth0.com/t/custom-claims-not-added-to-access-token-despite-rule/9460/19



https://auth0.com/docs/api-auth/tutorials/client-credentials/customize-with-hooks


## M2M application (non-interactive scripts)

This time we create last type - machine to machine application, and link
it with api created in Web application flow

Let's create direct route service

```
curl -i -X POST \
--url {{ kong }}/services/ \
--data 'name={{ m2mservice_name }}' \
--data 'url=https://httpbin.org/get'
```

Organize route for the service

```
curl -i -X POST \
--url {{ kong }}/services/{{ m2mservice_name }}/routes \
--data 'hosts[]={{domain}}&paths[]=/direct'
```

Now associate jwt plugin with service.

```
curl -i -X POST \
  --url {{kong}}/services/{{ m2mservice_name }}/plugins/ \
  --data 'name=jwt'
```

Now call to api will return `401 Unauthorized`

```
HTTP/1.1 401 Unauthorized
X-Kong-Response-Latency: 1
Server: kong/1.4.0

{
  "message": "Unauthorized"
}
```

How can we consume api ? We need to configure jwt consumer.

First of all, we need to get private key for message signing,

```
#!/bin/bash

COMPANYNAME=voronenko
curl -o ${COMPANYNAME}.pem "https://${COMPANYNAME}.auth0.com/pem"
openssl x509 -pubkey -noout -in ${COMPANYNAME}.pem > ${COMPANYNAME}.pub
```

Having that key, lets create kong consumer

```
curl -i -X POST \
  --url http://localhost:8001/consumers/ \
  --data "username={{auth0consumer}}&custom_id=someid2"
```

![alt](docs/06_kong_auth0_consumer.png)

and specify `jwt` method of the authentication for him:

```
#!/bin/bash

COMPANYNAME=voronenko
CONSUMERNAME=auth0voronenko
curl -i -X POST http://localhost:8001/consumers/${CONSUMERNAME}/jwt \
    -F "algorithm=RS256" \
    -F "rsa_public_key=@./${COMPANYNAME}.pub" \
    -F "key=https://${COMPANYNAME}.auth0.com/"
```

![alt](docs/07_kong_auth0_consumer_jwt_key.png)

At that moment we are ready to consume our api behind kong.

First of all, user obtains access token from Auth0:

```
curl --request POST \
  --url https://{{companyname}}.auth0.com/oauth/token \
  --header 'content-type: application/json' \
  --data '{"client_id":"R477zd0dhD0Hq3CnNIEgE677nwboYD5u","client_secret":"Omps9OmF5j_gNJBfc6byC3i6YuokRhVxtUG3THzEpKtOau8mgq9qAUZ6FxhxIHm2","audience":"https://implicitgrant.auth0.voronenko.net","grant_type":"client_credentials"}'

```

with response kind of

```
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IlF6bEZOak5CUmtZNVJqY3lOVVpCUmpJMU5qRkJOMFl4T0VNMVJFSXhNelU0TVVJeU5qa3dSUSJ9.eyJpc3MiOiJodHRwczovL3Zvcm9uZW5rby5hdXRoMC5jb20vIiwic3ViIjoiUjQ3N3pkMGRoRDBIcTNDbk5JRWdFNjc3bndib1lENXVAY2xpZW50cyIsImF1ZCI6Imh0dHBzOi8vaW1wbGljaXRncmFudC5hdXRoMC52b3JvbmVua28ubmV0IiwiaWF0IjoxNTc1NTgzNTM2LCJleHAiOjE1NzU2Njk5MzYsImF6cCI6IlI0Nzd6ZDBkaEQwSHEzQ25OSUVnRTY3N253Ym9ZRDV1IiwiZ3R5IjoiY2xpZW50LWNyZWRlbnRpYWxzIn0.aIx7LnT7aFPxmK4wCXxxGhEKrxPsGlZ3azEFykynkf6hfyb-4zCXlrqvxNjB9pk_PO8MxmKRJeoRsHLmNOvVls3tE90GQNa6DrqyWuO5PxZetkPyR56o5axt4PddZlop-mukiMYrZF2bP_gdRBZnhR2OJ4vU3qG6Rvs2k-J65tbb2oUERWps7KDC2FeTbV2bc09JtH25StNfYyHOPUR1MiDSKZbZqH3Z0bZUFHN1Ac7jznU3xUV8yEPTy7hQwOWUK5CxUSvd_s4RlTLKsHdAQWWxoDPRvxldwPXtxc7n13hwQPslJNR1ScbREcgJo4zPOcVM_uzTk1ygczLJCzvdsA",
  "expires_in": 86400,
  "token_type": "Bearer"
}
```

This request now passes, our API gets consumed.

```
@accessToken = {{accessTokenRequest.response.body.$.access_token}}

GET {{domain_endpoint}}/direct
authorization: Bearer {{accessToken}}
```

Additionally. we get bunch of headers:

```
  "headers": {
    "Accept-Encoding": "gzip, deflate",
    "Authorization": "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IlF6bEZOak5CUmtZNVJqY3lOVVpCUmpJMU5qRkJOMFl4T0VNMVJFSXhNelU0TVVJeU5qa3dSUSJ9.eyJpc3MiOiJodHRwczovL3Zvcm9uZW5rby5hdXRoMC5jb20vIiwic3ViIjoiUjQ3N3pkMGRoRDBIcTNDbk5JRWdFNjc3bndib1lENXVAY2xpZW50cyIsImF1ZCI6Imh0dHBzOi8vaW1wbGljaXRncmFudC5hdXRoMC52b3JvbmVua28ubmV0IiwiaWF0IjoxNTc1NTgzNTM2LCJleHAiOjE1NzU2Njk5MzYsImF6cCI6IlI0Nzd6ZDBkaEQwSHEzQ25OSUVnRTY3N253Ym9ZRDV1IiwiZ3R5IjoiY2xpZW50LWNyZWRlbnRpYWxzIn0.aIx7LnT7aFPxmK4wCXxxGhEKrxPsGlZ3azEFykynkf6hfyb-4zCXlrqvxNjB9pk_PO8MxmKRJeoRsHLmNOvVls3tE90GQNa6DrqyWuO5PxZetkPyR56o5axt4PddZlop-mukiMYrZF2bP_gdRBZnhR2OJ4vU3qG6Rvs2k-J65tbb2oUERWps7KDC2FeTbV2bc09JtH25StNfYyHOPUR1MiDSKZbZqH3Z0bZUFHN1Ac7jznU3xUV8yEPTy7hQwOWUK5CxUSvd_s4RlTLKsHdAQWWxoDPRvxldwPXtxc7n13hwQPslJNR1ScbREcgJo4zPOcVM_uzTk1ygczLJCzvdsA",
    "Cookie": "session=RvFnGF5MLqV5bO-gT9G_Sw..|1575567729|fVmDt5WSp1UFkU8CGCKbUKfvtdZAJQsuYRWFVAo8XZxYeNaZocUqdCltgzroNkLG7gd-wwsxBS2xrjumlOnPQTIyrbrbY9CALL1Px3ATwipnHeuqaVEabu1xXvJjOgnjAlFsJ7tq0G95hzsKaF2rtW1lYq_HRoWYK9NFbaxR0J5ZE7PBM6vIOJWZLzGEXn6FWM6MI0_vnm7SubOyOVPRHA..|LHlXUDxEsWwJhGbYfkmccT1fz2g.",
    "Host": "httpbin.org",
    "User-Agent": "vscode-restclient",
    "X-Consumer-Custom-Id": "someid2",
    "X-Consumer-Id": "954353fb-46e9-4be2-b4e6-a96ea468bcde",
    "X-Consumer-Username": "auth0voronenko",
    "X-Forwarded-Host": "app.lvh.voronenko.net"
  },
  ```

  Header after Bearer is again our jwt token, that can be decoded.

  ```
  {
  "iss": "https://voronenko.auth0.com/",
  "sub": "R477zd0dhD0Hq3CnNIEgE677nwboYD5u@clients",
  "aud": "https://implicitgrant.auth0.voronenko.net",
  "iat": 1575583536,
  "exp": 1575669936,
  "azp": "R477zd0dhD0Hq3CnNIEgE677nwboYD5u",
  "gty": "client-credentials"
}
```

and later consumed by our API.


## Extending Autho metadata


### Hooks

For M2M applications in difference to web based applications, where custom attributes can be injected via rules, point of extension are hooks.

Related documentation: https://auth0.com/docs/hooks

Take a look on a example below representing dummy `Client Credentials Exchange` hook extending access_token with additional keypair
`'https://foo.com/claim'`:`bar` and `somehookattr`:`somehookattrvalue`

```js

/**
@param {object} client - information about the client
@param {string} client.name - name of client
@param {string} client.id - client id
@param {string} client.tenant - Auth0 tenant name
@param {object} client.metadata - client metadata
@param {array|undefined} scope - array of strings representing the scope claim or undefined
@param {string} audience - token's audience claim
@param {object} context - additional authorization context
@param {object} context.webtask - webtask context
@param {function} cb - function (error, accessTokenClaims)
*/
module.exports = function(client, scope, audience, context, cb) {
  var access_token = {};
  access_token.scope = scope;

  // Modify scopes or add extra claims
  // access_token['https://example.com/claim'] = 'bar';
  // access_token.scope.push('extra');
  //client.metadata['yourcustomattrs'] = ['someattr3h', 'someattr4h'];
  //client.metadata.yourcustomattrs = ['someattr1h', 'someattr2h'];
  access_token['https://foo.com/claim'] = 'bar';
  access_token['https://foo.com/somehookattr'] = 'somehookattrvalue';
  access_token['somehookattr'] = 'somehookattrvalue';
  cb(null, access_token);
};

```

upon issuing request for token

```shell

curl --request POST \
  --url https://{{companyname}}.auth0.com/oauth/token \
  --header 'content-type: application/json' \
  --data '{"client_id":"R477zd0dhD0Hq3CnNIEgE677nwboYD5u","client_secret":"Omps9OmF5j_gNJBfc6byC3i6YuokRhVxtUG3THzEpKtOau8mgq9qAUZ6FxhxIHm2","audience":"https://implicitgrant.auth0.voronenko.net","grant_type":"client_credentials"}'

```

we receive following response

```
HTTP/1.1 200 OK
Date: Mon, 06 Jan 2020 11:58:45 GMT
Content-Type: application/json
Content-Length: 883
Connection: close
Server: nginx
ot-tracer-spanid: 19efb150187ac510
ot-tracer-traceid: 01032ad94083ad4d
ot-tracer-sampled: true
X-Auth0-RequestId: c629c3e05e0881e81315
X-RateLimit-Limit: 30
X-RateLimit-Remaining: 29
X-RateLimit-Reset: 1578311926
Cache-Control: no-store
Pragma: no-cache
Strict-Transport-Security: max-age=15724800
X-Robots-Tag: noindex, nofollow, nosnippet, noarchive

{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IlF6bEZOak5CUmtZNVJqY3lOVVpCUmpJMU5qRkJOMFl4T0VNMVJFSXhNelU0TVVJeU5qa3dSUSJ9.eyJodHRwczovL2Zvby5jb20vY2xhaW0iOiJiYXIiLCJodHRwczovL2Zvby5jb20vc29tZWhvb2thdHRyIjoic29tZWhvb2thdHRydmFsdWUiLCJpc3MiOiJodHRwczovL3Zvcm9uZW5rby5hdXRoMC5jb20vIiwic3ViIjoiUjQ3N3pkMGRoRDBIcTNDbk5JRWdFNjc3bndib1lENXVAY2xpZW50cyIsImF1ZCI6Imh0dHBzOi8vaW1wbGljaXRncmFudC5hdXRoMC52b3JvbmVua28ubmV0IiwiaWF0IjoxNTc4MzEyMTM4LCJleHAiOjE1NzgzOTg1MzgsImF6cCI6IlI0Nzd6ZDBkaEQwSHEzQ25OSUVnRTY3N253Ym9ZRDV1IiwiZ3R5IjoiY2xpZW50LWNyZWRlbnRpYWxzIn0.zwpoOLe93yTt9dXidsVfBPCujsOdC37dHGpxBepU0vEJ4hLB0PiKOgpHd6XCr4VqaZWshlCtyGgS7xUNHjvg7RyIOn8AyXXX2q2FRVkStXNB7p88HizF79dENLfX5jSDqpHMLiP7F1FjMlzCpLnB9x4NCR_vIt4HQDj5lOqI7B55q1gx7UKSzY1qgMzm1U8rl8BsA9tFoEMfMwEvhtHhVXdijo_-XbLkjmX-646V_Fl2bJUpkneZF5ZDR-lbh7qfp995UwpQBRqVfNhupOUP1_OyeOm19VP8ka0RBRdYhQGkSwSsFGQ07kHbe0md-d9fIO-AJYimaci37QvlTYQAXQ",
  "expires_in": 86400,
  "token_type": "Bearer"
}

```

Using debugger at jwt.io lets decode payload

```json

{
  "https://foo.com/claim": "bar",
  "https://foo.com/somehookattr": "somehookattrvalue",
  "iss": "https://voronenko.auth0.com/",
  "sub": "R477zd0dhD0Hq3CnNIEgE677nwboYD5u@clients",
  "aud": "https://implicitgrant.auth0.voronenko.net",
  "iat": 1578312138,
  "exp": 1578398538,
  "azp": "R477zd0dhD0Hq3CnNIEgE677nwboYD5u",
  "gty": "client-credentials"
}

```

Important: note, that extension attributes passed via custom namespaced
uri was allowed, while un-namespaced custom attribute `somehookattr` was
stripped out from the payload.


## Known issues

### No credentials found for given 'iss'

Please check, that `iss` returned in token payload,
should match to key field of the jwt token

In example above, `"iss": "https://voronenko.auth0.com/"` matches
to key attribute of the jwt key.

![alt](docs/07_kong_auth0_consumer_jwt_key.png)
