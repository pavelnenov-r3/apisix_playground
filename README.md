# Project Documentation: API Security with Keycloak & Apache APISIX

NOTE: This project follows https://apisix.apache.org/blog/2022/07/06/use-keycloak-with-api-gateway-to-secure-apis/
Plugins configured:
- `proxy-rewrite`: https://apisix.apache.org/docs/apisix/plugins/proxy-rewrite/
- `openid-connect`: https://apisix.apache.org/docs/apisix/plugins/openid-connect/

## 1. Overview

This document outlines the setup, configuration, and operational steps for securing APIs using Keycloak as the Identity and Access Management (IAM) solution and Apache APISIX as the API Gateway. It assumes you have a `docker-compose.yml` file that defines the necessary services (e.g., Apache APISIX, Keycloak, your backend services like `httpbin-service` and `simple-echo-service`).

The primary goal is to delegate authentication and authorization to Keycloak, with APISIX enforcing access policies for your upstream services. This includes scenarios where APISIX handles the OIDC redirects (`bearer_only: false`) and scenarios where it expects a pre-fetched token (`bearer_only: true`).

## 2. Prerequisites

Before you begin, ensure you have the following installed:

* **Docker**: To run the containerized services (Keycloak, APISIX, etc.).
* **Docker Compose**: To manage multi-container Docker applications (refer to your `docker-compose.yml`).
* **curl**: For testing API endpoints and interacting with APISIX Admin API.
* **jq (optional, recommended)**: For pretty-printing JSON responses from `curl`.

## 3. Initial Setup

### 3.1. Modify `/etc/hosts` File

To allow local resolution of the Keycloak server hostname from your machine and potentially from within Docker containers (depending on your Docker network setup), you need to modify your `/etc/hosts` file.

Add the following line to your `/etc/hosts` file. You might need administrator/sudo privileges to edit this file.

    127.0.0.1 keycloak-server your.api.local another.api.local

- `keycloak-server`: This allows your local machine and APISIX (if it's configured to resolve it this way) to reach Keycloak using this hostname (e.g., `http://keycloak-server:8180` as per your `docker-compose.yml`).

- `your.api.local`, `another.api.local`: Example hostnames for accessing your APIs through APISIX. Adjust as per your APISIX route configurations.

**Why?**

- `keycloak-server`: When APISIX's `openid-connect` plugin communicates with Keycloak, it will use the address configured. This entry ensures it resolves correctly.

- `your.api.local`, `another.api.local`: Allows testing APISIX routes using custom domain names.

## 4. Running the Project

1.  **Navigate to Project Directory**: Open your terminal and change to the directory where your `docker-compose.yml` file is located.
2.  **Start Services**: Run the following command to build (if necessary) and start all services in detached mode:

```bash
    docker-compose up -d
```
3.  **Verify Services**: Check the status of your running containers:

```bash
    docker-compose ps
```

    You should see all services (e.g., `apisix-gateway`, `keycloak-server`, `httpbin-service`, `simple-echo-service`) listed with a state of `Up`.
4.  **View Logs (Optional)**: To view the logs for a specific service:

```bash
    docker-compose logs -f <service_name_in_compose_file>
    # Example: docker-compose logs -f apisix
    # Example: docker-compose logs -f keycloak

```

## 5. Keycloak Configuration

Keycloak needs to be configured as the OIDC provider. Refer to \[Use Keycloak with API Gateway to Secure APIs (Apache APISIX Blog)\](https://apisix.apache.org/blog/2022/07/06/use-keycloak-with-api-gateway-to-secure-apis/) for background.

### 5.1. Initial Keycloak Admin Login

- Access Keycloak: `http://keycloak-server:8180` (or `http://localhost:8180`).

- Login with admin credentials (e.g., `admin`/`admin` from `docker-compose.yml`).

### 5.2. Realm Setup

- Create a new realm (e.g., `myrealm` as used in your example) or use an existing one.

### 5.3. Client Creation

Create clients in Keycloak for your APISIX integrations. You might have multiple clients depending on the authentication flow.

**Example Client for `bearer_only: true` (e.g., `apisix-client`):**

- **Client ID**: e.g., `apisix-client-bearer`

- **Client Protocol**: `openid-connect`

- **Access Type**: `confidential` or `bearer-only`.

- **Valid Redirect URIs**: For `bearer-only`, this is less critical for APISIX itself but would be important for the application that originally obtains the token.

- Note the **Client Secret** if `confidential`.

**Example Client for `bearer_only: false` (e.g., `apisix` used in your new example):**

- **Client ID**: e.g., `apisix` (as in your curl command)

- **Client Protocol**: `openid-connect`

- **Access Type**: `confidential` (as it needs a secret to interact with token endpoint, etc.).

- **Valid Redirect URIs**: **CRITICAL**. This list -must- include the `redirect_uri` configured in the APISIX `openid-connect` plugin for the corresponding route. For your example, this would be `http://localhost:9080/test-echo/callback`. Add this exact URI.

- **Web Origins**: Set `+` or specific origins for CORS.

- Note the **Client Secret** (e.g., `ZAiFjnpip460Yq65rMwf2oDinZ8pNRpF` from your example).

### 5.4. (Optional) Client Scopes and Mappers

- Configure client scopes (e.g., `openid`, `profile`, `email`) and mappers as needed.

### 5.5. Obtain OIDC Discovery Endpoint

- URL: `http://keycloak-server:8180/realms/{your-realm-name}/.well-known/openid-configuration` (e.g., `http://keycloak-server:8180/realms/myrealm/.well-known/openid-configuration`)

## 6. Apache APISIX Configuration

APISIX is configured via its Admin API (default port `9180`).

### 6.1. APISIX Admin API Key (`X-API-KEY`)

- Defined in `./apisix_conf/config.yaml` (mounted in `docker-compose.yml`).

- **Example `config.yaml` snippet**:

```

apisix:

    admin\_key:

      - name: "admin"

        key: "YOUR\_CHOSEN\_ADMIN\_API\_KEY" # Replace with your key

        role: admin

```

- The default key is `edd1c9f034335f136f87ad84b625c8f1`. **Change this for security.** Your provided `curl` uses this default.

### 6.2. Key Concepts in APISIX

- **Upstream**: Your backend service (e.g., `httpbin-service`, `simple-echo-service`).

- **Route**: Maps client requests to Upstreams and applies plugins.

- **Plugins**:

- `openid-connect`: Integrates with Keycloak.

- `proxy-rewrite`: Modifies requests/responses, often used for header manipulation.

### 6.3. Example `curl` Commands for APISIX Setup

#### 6.3.1. Add an Upstream (e.g., HTTPBin Service for `bearer_only: true` example)

This is for a route where APISIX expects a pre-fetched token.

```

curl -X PUT 'http://localhost:9180/apisix/admin/upstreams/httpbin-upstream' \\

\-H 'X-API-KEY: YOUR_CHOSEN_ADMIN_API_KEY' \\

\-H 'Content-Type: application/json' \\

\-d '{

    "name": "HTTPBin Service",

    "type": "roundrobin",

    "nodes": {

        "httpbin-service:80": 1

    }

}'

```

#### 6.3.2. Add a Route with `openid-connect` (`bearer_only: true`)

Protects an API, expecting the client to send a `Bearer` token.

```

curl -X PUT 'http://localhost:9180/apisix/admin/routes/keycloak-bearer-route' \\

\-H 'X-API-KEY: YOUR_CHOSEN_ADMIN_API_KEY' \\

\-H 'Content-Type: application/json' \\

\-d '{

    "name": "Secure API Route with Keycloak (Bearer Only)",

    "uri": "/bearer-test/-",

    "hosts": \["your.api.local"\],

    "upstream_id": "httpbin-upstream",

    "plugins": {

        "openid-connect": {

            "client\_id": "apisix-client-bearer", # Use appropriate client\_id from Keycloak

            "client\_secret": "YOUR\_BEARER\_CLIENT\_SECRET", # If client is confidential

            "discovery": "http://keycloak-server:8180/realms/myrealm/.well-known/openid-configuration",

            "bearer\_only": true,

            "realm": "myrealm",

            "scope": "openid profile email",

            "set\_userinfo\_header": true,

            "userinfo\_header\_name": "X-Userinfo-Bearer"

        }

    }

}'

```

#### 6.3.3. Add a Route with `openid-connect` (`bearer_only: false`) and `proxy-rewrite` (Your Provided Example)

This route will have APISIX manage the OIDC login flow (redirects to Keycloak) and then rewrite headers before proxying to the `simple-echo-service`.

```bash
curl -X PUT 'http://127.0.0.1:9180/apisix/admin/routes/5' \                                           
-H 'X-API-KEY: edd1c9f034335f136f87ad84b625c8f1' \
-H 'Content-Type: application/json' \
-d '{
    "name": "simple-echo-oidc-protected-with-proxy-rewrite-v3",
    "uri": "/test-echo/*",
    "methods": ["GET", "POST", "PUT", "DELETE", "PATCH"],
    "plugins": {
        "openid-connect": {
            "client_id": "apisix",
            "client_secret": "ZAiFjnpip460Yq65rMwf2oDinZ8pNRpF",
            "discovery": "http://keycloak-server:8180/realms/myrealm/.well-known/openid-configuration",
            "scope": "openid profile email",
            "bearer_only": false,
            "realm": "myrealm",
            "redirect_uri": "http://localhost:9080/test-echo/callback",
            "logout_path": "/test-echo/logout",
            "set_access_token_header": true,
            "access_token_header": "X-Access-Token",
            "set_id_token_header": true,
            "id_token_header": "X-Id-Token",
            "set_userinfo_header": true,
            "userinfo_header": "X-Userinfo",
            "token_endpoint_auth_method": "client_secret_post",
            "introspection_endpoint_auth_method": "client_secret_post"
        },
        "proxy-rewrite": {
            "headers": {
                "set": {
                    "Authorization": "Bearer $http_x_access_token"
                },
                "remove": [
                    "X-Access-Token", "x-userinfo", "cookie", "x-id-token"
                ]
            }
        }
    },
    "upstream": {
        "type": "roundrobin",
        "nodes": {
            "simple-echo-service:8080": 1
        },
        "scheme": "http"
    },
    "status": 1
}'
```

**Notes on this example:**

- `bearer_only: false`: APISIX handles the OIDC Authorization Code Flow. When an unauthenticated user accesses `/test-echo/*`, APISIX redirects them to Keycloak.

- `redirect_uri`: `http://another.api.local:9080/test-echo/callback`. This is where Keycloak redirects back after login. This URI (host and path) must be registered in the Keycloak client's "Valid Redirect URIs". The hostname `another.api.local` and port `9080` should match how users access APISIX.

- `proxy-rewrite`: After successful authentication, this plugin modifies headers. It takes the access token from the `X-Access-Token` header (set by `openid-connect`) and puts it into the `Authorization: Bearer` header for the upstream service. It also cleans up other headers.

- Upstream `simple-echo-service:8080` is defined inline. This service is available from your `docker-compose.yml`.

### 6.4. Other `curl` Commands

**Listing Routes:**

```

curl -X GET 'http://localhost:9180/apisix/admin/routes' \\

\-H 'X-API-KEY: YOUR_CHOSEN_ADMIN_API_KEY' | jq .

```

## 7. How to Test

### 7.1. Testing `bearer_only: true` Route (e.g., `/bearer-test/*`)

1.  **Obtain Token from Keycloak (Password Grant):** -(-Ensure Password Grant is enabled for the `apisix-client-bearer` client in Keycloak and the user has a password.)-

    ```

    KEYCLOAK_URL="http://keycloak-server:8180"

    REALM_NAME="myrealm"

    CLIENT_ID="apisix-client-bearer" # Client for bearer only

    CLIENT_SECRET="YOUR_BEARER_CLIENT_SECRET"

    USERNAME="YOUR_KEYCLOAK_USER"

    PASSWORD="YOUR_KEYCLOAK_USER_PASSWORD"

    TOKEN_RESPONSE=$(curl -s -X POST \\

        "${KEYCLOAK_URL}/realms/${REALM_NAME}/protocol/openid-connect/token" \\

        -H "Content-Type: application/x-www-form-urlencoded" \\

        -d "username=${USERNAME}" -d "password=${PASSWORD}" \\

        -d "client\_id=${CLIENT_ID}" -d "client_secret=${CLIENT_SECRET}" \\

        -d "grant_type=password" -d "scope=openid profile email")

    ACCESS_TOKEN=$(echo $TOKEN_RESPONSE | jq -r .access_token)

    echo "Access Token: $ACCESS_TOKEN"

    ```

2.  **Access Protected API via APISIX:**

    ```

    curl -i \[http://your.api.local:9080/bearer-test/get\](http://your.api.local:9080/bearer-test/get) \\

    \-H "Authorization: Bearer $ACCESS_TOKEN"

    ```

    You should see headers from `httpbin-service` and `X-Userinfo-Bearer`.

### 7.2. Testing `bearer_only: false` Route (e.g., `/test-echo/*`)

1.  **Initiate Login Flow:** Open your web browser and navigate to `http://another.api.local:9080/test-echo/headers` (or any path under `/test-echo/`).

2.  APISIX (via the `openid-connect` plugin) should redirect you to the Keycloak login page.

3.  Log in with a user from your `myrealm` realm in Keycloak.

4.  After successful login, Keycloak will redirect you back to the `redirect_uri` specified in the plugin (`http://another.api.local:9080/test-echo/callback`).

5.  APISIX will handle the callback, obtain tokens, and then proxy the original request to `simple-echo-service`.

6.  You should see the response from `simple-echo-service`. If you inspect the request received by `simple-echo-service` (e.g., by checking its logs or if it echoes headers), you should find the `Authorization: Bearer <token>` header set by the `proxy-rewrite` plugin, and the other headers like `X-Access-Token` removed.

**To Logout (for `bearer_only: false` route):** Navigate to `http://another.api.local:9080/test-echo/logout` in your browser. This should trigger the OIDC logout flow.

## 8. What is Going On? (System Architecture)

1.  **Docker & Docker Compose**: Manage services.
2.  **`/etc/hosts`**: Local DNS.
3.  **Keycloak (IAM)**: Central identity provider.
4.  **Apache APISIX (API Gateway)**:

    - **Admin API (`9180`)**: For configuration.

    - **Proxy Interface (`9080` HTTP / `9443` HTTPS)**: For client requests.

    - **`openid-connect` plugin**:

        - `bearer_only: true`: Validates existing Bearer token.

        - `bearer_only: false`: Manages OIDC redirect flow, obtains tokens, sets session cookies.

    - **`proxy-rewrite` plugin**: Modifies request/response headers or other parts of the request before sending to upstream.

5.  **Backend Service(s)**: Receive requests after APISIX processing.

## 9. Troubleshooting

-(-Troubleshooting section remains largely the same, ensure to check specific client IDs, secrets, and redirect URIs based on the route being tested.)-

- **Cannot connect to `your.api.local`, `another.api.local` or `keycloak-server`**: Check `/etc/hosts`, `docker-compose ps`, ports.

- **APISIX Admin API issues**: Check APISIX logs, `X-API-KEY`.

- **Keycloak Admin Console issues**: Check Keycloak logs.

- **`401 Unauthorized` from APISIX**:

- For `bearer_only: true`: Invalid/expired token, incorrect plugin config.

- For `bearer_only: false`: Misconfigured `redirect_uri` in Keycloak client vs. APISIX plugin, client secret mismatch, Keycloak client not enabled.

- **Redirect Loops or Callback Issues (`bearer_only: false`)**:

- `redirect_uri` in APISIX must exactly match one in Keycloak client's "Valid Redirect URIs".

- Check APISIX and Keycloak logs for OIDC errors.

- **`proxy-rewrite` not working**: Check APISIX logs for errors. Ensure variable names (e.g., `$http_x_access_token`) are correct and the source headers are being set as expected by the preceding `openid-connect` plugin.

- **APISIX cannot connect to Keycloak**: Network issues, incorrect discovery URL.

- **`404 Not Found` from APISIX**: Route definition (`uri`, `hosts`) mismatch.

- **Password Grant issues**: Ensure grant is enabled in Keycloak client, correct credentials.
