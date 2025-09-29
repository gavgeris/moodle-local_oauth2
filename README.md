# Matrix-Moodle SSO Integration με OIDC

Το plugin αυτό επιτρέπει την διασύνδεση Single Sign-On ανάμεσα σε Matrix server και Moodle χρησιμοποιώντας OIDC (OpenID Connect).

## Infrastructure

- **Moodle**: https://learn.dimos.sch.gr (με CAS authentication από sch.gr)
- **Matrix**: https://matrix.dimos.dev.ellak.gr
- **Element**: https://chat.dimos.dev.ellak.gr
- **Target room**: `#rooma:matrix.dimos.dev.ellak.gr`

## Moodle Setup

### Prerequisites

- **OAuth2 plugin**: [local_oauth2](https://github.com/gavgeris/moodle-local_oauth2.git)
- **OAuth client**: `matrix-dimos-client`
- **Scopes**: `openid profile email login` (space-separated)

## Αρχεία που Δημιουργήθηκαν

```
/local/oauth2/
├── jwks.php                    # JWKS endpoint
├── userinfo.php                # UserInfo endpoint
├── token_oidc.php              # Custom token endpoint with id_token
├── openid_configuration.php    # Discovery document
├── create_keys.php             # Key generation script
└── debug_token.php             # Debug script
```

### File Descriptions

| File | Purpose |
|------|---------|
| `jwks.php` | Provides JSON Web Key Set for JWT signature verification |
| `userinfo.php` | Returns user information claims |
| `token_oidc.php` | Handles token exchange and generates id_token (JWT) |
| `openid_configuration.php` | OpenID Connect discovery document |
| `create_keys.php` | Generates RSA key pair and stores in database |
| `debug_token.php` | Debug utility to test token generation |

## Matrix Configuration

Add the following to your Matrix `homeserver.yaml`:

```yaml
enable_registration: true
enable_registration_without_verification: true

oidc_providers:
  - idp_id: moodle_dimos
    idp_name: "Σύνδεση με ΔΗΜΩΣ"
    discover: false
    authorization_endpoint: "https://learn.dimos.sch.gr/local/oauth2/login.php"
    token_endpoint: "https://learn.dimos.sch.gr/local/oauth2/token_oidc.php"
    userinfo_endpoint: "https://learn.dimos.sch.gr/local/oauth2/userinfo.php"
    jwks_uri: "https://learn.dimos.sch.gr/local/oauth2/jwks.php"
    issuer: "https://learn.dimos.sch.gr/local/oauth2"
    client_id: "matrix-dimos-client"
    client_secret: "YOUR_CLIENT_SECRET_HERE"  # The secret key from Moodle
    client_auth_method: "client_secret_post"
    scopes: ["openid", "profile", "email", "login"]
    user_mapping_provider:
      config:
        localpart_template: "{{ user.preferred_username }}"
        display_name_template: "{{ user.name }}"
        email_template: "{{ user.email }}"
    allow_existing_users: true
```

## Installation Steps

### 1. Install Moodle OAuth2 Plugin

```bash
cd /path/to/moodle/local
git clone https://github.com/gavgeris/moodle-local_oauth2.git oauth2
```

### 2. Create OAuth Client in Moodle

1. Navigate to: **Site Administration > Server > OAuth2 server > Manage OAuth clients**
2. Click **Add OAuth client**
3. Fill in:
    - **Client Name**: Matrix DIMOS
    - **Client Identifier**: `matrix-dimos-client`
    - **Redirect URI**: `https://matrix.dimos.dev.ellak.gr/_synapse/client/oidc/callback`
    - **Scopes**: `openid profile email login`
4. Save and note the generated **Client Secret**


### 3. Verify Endpoints

Test each endpoint:

```bash
# JWKS endpoint
curl https://learn.dimos.sch.gr/local/oauth2/jwks.php

# Discovery document
curl https://learn.dimos.sch.gr/local/oauth2/openid_configuration.php

# UserInfo (requires access token)
curl -H "Authorization: Bearer YOUR_TOKEN" \
     https://learn.dimos.sch.gr/local/oauth2/userinfo.php
```

### 4. Configure Matrix

Add the configuration from "Matrix Configuration" section to your `homeserver.yaml`.

### 8. Restart Matrix

```bash
docker-compose restart matrix-synapse
# or
systemctl restart matrix-synapse
```

## Usage

### Direct Room Links

Users can access Matrix rooms directly from Moodle using URLs like:

```
https://chat.dimos.dev.ellak.gr/#/room/#rooma:matrix.dimos.dev.ellak.gr
```

When not authenticated, they will be redirected to:
1. Moodle OAuth authorization
2. CAS authentication (if not logged in to Moodle)
3. Back to Matrix with SSO credentials

### OAuth Flow

1. **User clicks Matrix login** → Redirected to Moodle
2. **Moodle authenticates** → Via CAS if needed
3. **User authorizes Matrix** → Consent screen
4. **Authorization code** → Sent back to Matrix
5. **Token exchange** → Matrix gets access_token + id_token
6. **User creation/login** → Matrix creates/logs in user

## Troubleshooting

### Check Logs

**Matrix logs:**
```bash
docker logs matrix-synapse -f
```

**Moodle logs:**
```bash
docker exec -it moodle bash
tail -f /opt/bitnami/apache/logs/error_log
```

### Common Issues

#### 404 Error on Token Endpoint
- Verify file exists: `/local/oauth2/token_oidc.php`
- Check file permissions: `644`
- Verify web server can read the file

#### Invalid Scope Error
- Ensure scopes in Moodle client match Matrix config
- Scopes must be space-separated in Moodle

#### Missing id_token Error
- Run `create_keys.php` to generate RSA keys
- Verify keys exist in database:
```sql
SELECT * FROM mdl_local_oauth2_public_key WHERE client_id = 'global_jwks_key';
```

#### JWKS Error
- Test JWKS endpoint manually
- Verify RSA keys are properly formatted
- Check OpenSSL is available: `php -m | grep openssl`

### Debug Mode

Use the debug script to test token generation:

```
https://learn.dimos.sch.gr/local/oauth2/debug_token.php
```

## Security Considerations

- Store client secrets securely
- Use HTTPS for all endpoints
- Regularly rotate RSA keys
- Monitor OAuth access logs
- Restrict redirect URIs to trusted domains

## License

CC-BY-SA

## Contributors


## Support

For issues and questions, please open an issue on GitHub.