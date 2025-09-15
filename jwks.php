<?php
require_once(__DIR__ . '/../../config.php');

try {
    // Get public key from database
    $keyrecord = $DB->get_record('local_oauth2_public_key', ['client_id' => 'global_jwks_key']);
    
    if (!$keyrecord || !$keyrecord->public_key) {
        throw new Exception('Public key not found in database');
    }
    
    $publickey = $keyrecord->public_key;
    
    // Parse public key
    $keyresource = openssl_pkey_get_public($publickey);
    if (!$keyresource) {
        throw new Exception('Invalid public key format');
    }
    
    $keydetails = openssl_pkey_get_details($keyresource);
    if (!$keydetails || !isset($keydetails['rsa'])) {
        throw new Exception('Invalid RSA key details');
    }
    
    // Convert to base64url
    $n = rtrim(strtr(base64_encode($keydetails['rsa']['n']), '+/', '-_'), '=');
    $e = rtrim(strtr(base64_encode($keydetails['rsa']['e']), '+/', '-_'), '=');
    
    $jwks = [
        'keys' => [
            [
                'kty' => 'RSA',
                'use' => 'sig',
                'kid' => 'global_key',
                'alg' => 'RS256',
                'n' => $n,
                'e' => $e
            ]
        ]
    ];
    
    header('Content-Type: application/json');
    echo json_encode($jwks, JSON_PRETTY_PRINT);
    
} catch (Exception $e) {
    header('HTTP/1.1 500 Internal Server Error');
    header('Content-Type: application/json');
    echo json_encode(['error' => 'server_error', 'error_description' => $e->getMessage()]);
}
?>
