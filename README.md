# Ory Hydra/Kratos Integration in Go

## Getting Started

- Startup the containers with the following command:

```shell
docker-compose up -d --build
```

- Create an OAuth client with the following command:

```shell
curl -X POST 'http://localhost:4445/clients' \
-H 'Content-Type: application/json' \
--data-raw '{
  "client_id": "auth-code-client",
  "client_name": "Test OAuth2 Client",
  "client_secret": "secret",
  "grant_types": ["authorization_code", "refresh_token"],
  "redirect_uris": ["http://localhost:4455/dashboard"],
  "response_types": ["code", "id_token"],
  "scope": "openid offline",
  "token_endpoint_auth_method": "client_secret_post",
  "metadata": {"registration": true}
}'
```

Note: You can turn off registration by setting the `registration` property to `false` in the `metadata` property above.

- Open [localhost:4455/login](http://localhost:4455) in your browser.

- Register a new account and verify the email address by opening [localhost:4436/login](http://localhost:4436) in your browser.

- You can now successfully login!

## Ory Hydra/Kratos Integration Flow

![alt text](https://github.com/atreya2011/go-kratos-test/blob/hydra/docs/flow.png?raw=true)
