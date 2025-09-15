<?php
use core\session\manager;
use OAuth2\Request;
use OAuth2\Response;

require_once(__DIR__ . '/../../config.php');
manager::write_close();

// OAuth2 lib
require_once($CFG->dirroot . '/local/oauth2/vendor/bshaffer/oauth2-server-php/src/OAuth2/Autoloader.php');
OAuth2\Autoloader::register();

// Πάρε server & request
$server  = local_oauth2\utils::get_oauth_server();
$request = Request::createFromGlobals();
$response = new Response();

// 1) Άφησε τον OAuth2 server να χειριστεί το token request (authorization_code | refresh_token κτλ)
$server->handleTokenRequest($request, $response);

// Αν απέτυχε, στείλ’ το όπως είναι.
if ($response->getStatusCode() !== 200) {
    $response->send();
    exit;
}

// 2) Πάρε τα params του επιτυχούς token response
$params = $response->getParameters();
// Περιμένουμε τουλάχιστον access_token, expires_in, token_type, scope (ανάλογα με το grant)
// Θα προσθέσουμε id_token

try {
    global $DB;

    // === Φόρτωσε το private key που ταιριάζει με το JWKS (kid: global_key) ===
    $keyrecord = $DB->get_record('local_oauth2_public_key', ['client_id' => 'global_jwks_key']);
    if (!$keyrecord || empty($keyrecord->private_key)) {
        throw new \Exception('OIDC signing key not found in DB (client_id=global_jwks_key).');
    }
    $privatePem = $keyrecord->private_key;
    $pkey = openssl_pkey_get_private($privatePem);
    if (!$pkey) {
        throw new \Exception('Invalid private key (cannot open).');
    }

    // === Βρες client_id & user ===
    // Από το request:
    $clientId = $request->request('client_id');
    if (!$clientId) {
        // Κάποιοι clients στέλνουν client_id στο Authorization header ή μέσω basic—επίλεξε τη δική σου ροή.
        // Για Synapse με client_secret_post είναι εδώ.
        $clientId = optional_param('client_id', null, PARAM_TEXT);
    }
    if (!$clientId) {
        throw new \Exception('Missing client_id in token request.');
    }

    // Από το access token πρέπει να ανακτήσουμε τον user. Με τον bshaffer server:
    $stor = local_oauth2\utils::get_oauth_storage();
    $accesstoken = $params['access_token'] ?? null;
    if (!$accesstoken) {
        throw new \Exception('No access_token to bind user for id_token.');
    }
    $tokendata = $stor->getAccessToken($accesstoken);
    if (!$tokendata || empty($tokendata['user_id'])) {
        throw new \Exception('Cannot resolve user from access_token.');
    }
    $user = $DB->get_record('user', ['id' => $tokendata['user_id']], '*', MUST_EXIST);

    // === Συναρμολόγηση id_token (RS256) ===
    $now  = time();
    $iat  = $now;
    $exp  = $now + 3600; // προσαρμόσιμο
    $iss  = rtrim($CFG->wwwroot, '/') . '/local/oauth2'; // πρέπει να ταιριάζει ακριβώς με το issuer του Synapse config
    $sub  = (string)$user->username; // ή user->id – αλλά μείνε συνεπής παντού
    $aud  = $clientId;

    $header = [
        'typ' => 'JWT',
        'alg' => 'RS256',
        'kid' => 'global_key'
    ];

    $payload = [
        'iss' => $iss,
        'sub' => $sub,
        'aud' => $aud,
        'exp' => $exp,
        'iat' => $iat,
        // OIDC profile claims:
        'name' => fullname($user),
        'email' => $user->email,
        'preferred_username' => $user->username,
        'email_verified' => true
    ];

    $headerEncoded  = rtrim(strtr(base64_encode(json_encode($header)), '+/', '-_'), '=');
    $payloadEncoded = rtrim(strtr(base64_encode(json_encode($payload)), '+/', '-_'), '=');
    $toSign = $headerEncoded . '.' . $payloadEncoded;

    $signature = '';
    if (!openssl_sign($toSign, $signature, $pkey, OPENSSL_ALGO_SHA256)) {
        throw new \Exception('Failed to sign id_token (RS256).');
    }
    $sigEncoded = rtrim(strtr(base64_encode($signature), '+/', '-_'), '=');
    $idToken = $toSign . '.' . $sigEncoded;

    // 3) Ενσωμάτωσε το id_token και στείλε JSON
    $params['id_token'] = $idToken;

    // Στείλε καθαρό JSON (ο Response του bshaffer ήδη έδωσε headers — ξαναστείλ’ τα σωστά)
    header_remove(); // καθάρισε headers από προηγούμενο send
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($params, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;

} catch (\Throwable $e) {
    http_response_code(500);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode([
        'error' => 'server_error',
        'error_description' => 'id_token generation failed: ' . $e->getMessage()
    ]);
    exit;
}
