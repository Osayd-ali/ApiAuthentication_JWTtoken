## Authenticating Rest APIs using JWT tokens

Authenticating RESTful apis using JWT tokens. Eliminating server side sessions for every login. Providing Stateless authentication for apis.

1. REST APIs are stateless by design: each request should be self contained and should not rely on a server side session.
2. JWTs (JSON web tokens) provide a way to authenticate users without server-side sessions. After login, the server issues a token (a signed string) that contains user information. The client stores the token (usually in memory or local storage) and sends it with every request.
3. This allows Spring Boot to verify each request without keeping track of logged in users, making it perfect for scalable RESTful services.

## Authentication flow with JWT
* The user logs in by sending their username and password to /login.
* The server authenticates the user and returns a JWT.
* The client stores the JWT (usually in local storage or an HTTP only cookie).
* For every future request, the client includes the token in the authorization header.
* A filter on the server parses and validates the token.
* If valid, Spring sets the SecurityContext and the request proceeds.
* No session is stored on the server - everything needed is inside the token.
