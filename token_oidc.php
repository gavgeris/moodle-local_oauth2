<?php
use core\session\manager;
use OAuth2\Request;
use OAuth2\Response;

require_once(__DIR__ . '/../../config.php');
manager::write_close();

// OAuth2 lib bootstrap
require_once($CFG->dirroot . '/local/oauth2/vendor/bshaffer/oauth2-server-php/src/OAuth2/Autoloader.php');
OAuth2\Autoloader::register();

/** @var \OAuth2\Server $server */
$server  = local_oauth2\utils::get_oauth_server();
$request = Request::createFromGlobals();
$response = new Response();

// 1) Let the OAuth2 server handle the token exchange (authorization_code / refresh_token)
$server->handleTokenRequest($request, $response);

// If the OAuth2 exchange failed, return that as-is (JSON error)
if ($response->getStatusCode() !== 200) {
    $response->send();
    exit;
}

// Successful parameters (access_token, token_type, expires_in, scope, maybe refresh_token)
$params = $response->getParameters();

try {
    global $DB;

    // --- Load RSA private key matching your JWKS (kid = "global_key") ---
    // Adjust this selector if you store the key differently.
    $keyrecord = $DB->get_record('local_oauth2_public_key', ['client_id' => 'global_jwks_key']);
    if (!$keyrecord || empty($keyrecord->private_key)) {
        throw new \Exception('OIDC signing key not found in DB (client_id=global_jwks_key).');
    }
    $privatePem = $keyrecord->private_key;
    $pkey = openssl_pkey_get_private($privatePem);
    if (!$pkey) {
        throw new \Exception('Invalid private key (cannot open).');
    }

    // --- Resolve client_id (Synapse uses client_secret_post) ---
    $clientId = $request->request('client_id');
    if (!$clientId) {
        $clientId = optional_param('client_id', null, PARAM_TEXT);
    }
    if (!$clientId) {
        throw new \Exception('Missing client_id in token request.');
    }

    // --- Resolve user from the issued access_token using the storage directly ---
    $accessToken = $params['access_token'] ?? null;
    if (!$accessToken) {
        throw new \Exception('No access_token present to bind user for id_token.');
    }

    $storage = $server->getStorage('access_token');
    if (!$storage) {
        throw new \Exception('Access token storage not available.');
    }

    // bshaffer storage returns: user_id, expires, scope, client_id, etc.
    $tokendata = $storage->getAccessToken($accessToken);
    if (!$tokendata || empty($tokendata['user_id'])) {
        throw new \Exception('Cannot resolve user from access_token.');
    }

    // Load Moodle user
    $user = $DB->get_record('user', ['id' => $tokendata['user_id']], '*', MUST_EXIST);

    // Get the authorization code from the token request
    $authCode = $request->request('code');
    if (!$authCode) {
        $authCode = optional_param('code', null, PARAM_RAW_TRIMMED);
    }

    // Lookup nonce and delete (one-time use)
    $nonce = null;
    if (!empty($authCode)) {
        if ($rec = $DB->get_record('local_oauth2_nonce', ['code' => $authCode])) {
            $nonce = $rec->nonce;
            $DB->delete_records('local_oauth2_nonce', ['code' => $authCode]);
        }
    }


    // --- Build RS256 id_token ---
    $now = time();
    $iat = $now;
    // Prefer the OAuth2 expiry if available; else 3600
    $exp = !empty($tokendata['expires']) ? (int)$tokendata['expires'] : ($now + 3600);

    // Issuer must match Synapse's `issuer` config EXACTLY
    $iss = rtrim($CFG->wwwroot, '/') . '/local/oauth2';
    $aud = $clientId;
    // Stable subject (username or user id). Keep it consistent with your user mapping.
    $sub = (string)$user->username;

    $header = [
        'typ' => 'JWT',
        'alg' => 'RS256',
        'kid' => 'global_key',
    ];

    $payload = [
        'iss' => $iss,
        'sub' => $sub,
        'aud' => $aud,
        'exp' => $exp,
        'iat' => $iat,

        // Standard OIDC profile claims Synapse can map
        'name' => fullname($user),
        'email' => $user->email,
        'preferred_username' => $user->username,
        'email_verified' => true,
    ];

    if (!empty($nonce)) {
        $payload['nonce'] = $nonce;
    }

    $b64url = function ($data) {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    };

    $headerEncoded  = $b64url(json_encode($header, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
    $payloadEncoded = $b64url(json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
    $toSign = $headerEncoded . '.' . $payloadEncoded;

    $signature = '';
    if (!openssl_sign($toSign, $signature, $pkey, OPENSSL_ALGO_SHA256)) {
        throw new \Exception('Failed to sign id_token (RS256).');
    }
    $sigEncoded = $b64url($signature);
    $idToken = $toSign . '.' . $sigEncoded;

    // Attach id_token to the token response
    $params['id_token'] = $idToken;

    // Return clean JSON
    header_remove();
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($params, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;

} catch (\Throwable $e) {
    http_response_code(500);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode([
        'error' => 'server_error',
        'error_description' => 'id_token generation failed: ' . $e->getMessage(),
    ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;
}
