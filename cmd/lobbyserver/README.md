lobbyserver
===========

Demo server for the tachyon protocol.

## OAuth2 support

Server supports following OAuth2 RFCs:
- [RFC 6749](https://tools.ietf.org/html/rfc6749) - The OAuth 2.0 Authorization Framework
- [RFC 6750](https://tools.ietf.org/html/rfc6750) - The OAuth 2.0 Authorization Framework: Bearer Token Usage
- [RFC 7636](https://tools.ietf.org/html/rfc7636) - Proof Key for Code Exchange by OAuth Public Clients
- [RFC 8252](https://tools.ietf.org/html/rfc8252) - OAuth 2.0 for Native Apps
- [RFC 8414](https://tools.ietf.org/html/rfc8414) - OAuth 2.0 Authorization Server Metadata

Planned:
- [RFC 7009](https://tools.ietf.org/html/rfc7009) - OAuth 2.0 Token Revocation
- [RFC 7662](https://tools.ietf.org/html/rfc7662) - OAuth 2.0 Token Introspection

Considered:
- [RFC 7523](https://tools.ietf.org/html/rfc7523) - JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and Authorization Grants
- [RFC 8693](https://tools.ietf.org/html/rfc8693) - OAuth 2.0 Token Exchange

The servers also tries to follow the [OAuth 2.0 Security Best Current Practice](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics) and the [OAuth 2.1 draft](https://oauth.net/2.1/).

## OAuth2 authentication

Below is the example flow of the OAuth2 authentication process for the lobbyserver:

1. Go to https://developer.pingidentity.com/en/tools/pkce-code-generator.html and generate a code verifier and code challenge.
2. Open http://localhost:8080/oauth2/authorize?response_type=code&redirect_uri=http%3A%2F%2F127.0.0.1%3A9090%2Foauth2callback&client_id=lobby&code_challenge_method=S256&code_challenge={code_challenge}
3. Login with username `user1@example.com` and password `user1pass`.
4. Copy the `code` parameter from the redirect url.
5. Run the following curl command to get an access token:

   ```
   curl -X POST http://localhost:8080/oauth2/token \
       --user lobby: \
       -d grant_type=authorization_code \
       -d redirect_uri=http%3A%2F%2F127.0.0.1%3A9090%2Foauth2callback \
       -d code={authorization_code} \
       -d code_verifier={code_verifier}
   ```
6. Check access token works:

   ```
   curl curl -H "Authorization: Bearer {access_token}" http://localhost:8080/oauth2/test
   ```
