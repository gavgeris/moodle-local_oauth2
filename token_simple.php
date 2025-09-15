<?php
// Simple OIDC token endpoint without JWT signing
error_reporting(E_ALL);
ini_set('display_errors', 1);

use core\session\manager;
use OAuth2\Request;

require_once(__DIR__ . '/../../config.php');

manager::write_close();

try {
    // Load OAuth2 library
    require_once($CFG->dirroot . '/local/oauth2/vendor/bshaffer/oauth2-server-php/src/OAuth2/Autoloader.php');
    OAuth2\Autoloader::register();
    
    $server = local_oauth2\utils::get_oauth_server();
    $request = Request::createFromGlobals();
    $response = new \OAuth2\Response();
    
    // Handle the token request normally first
    $tokenResponse = $server->handleTokenRequest($request, $response);
    
    if ($tokenResponse->getStatusCode() == 200) {
        $tokenData = json_decode($tokenResponse->getContent(), true);
        
        // Add a simple unsigned id_token for testing
        $scope = $request->request('scope', '');
        if (strpos($scope, 'openid') !== false) {
            $tokenData['id_token'] = createSimpleIdToken($request, $tokenData);
        }
        
        header('Content-Type: application/json');
        echo json_encode($tokenData);
    } else {
        $tokenResponse->send();
    }
    
} catch (Exception $e) {
    header('HTTP/1.1 500 Internal Server Error');
    header('Content-Type: application/json');
    $error = [
        'error' => 'server_error', 
        'error_description' => $e->getMessage(),
        'debug' => [
            'file' => $e->getFile(),
            'line' => $e->getLine(),
            'trace' => $e->getTraceAsString()
        ]
    ];
    echo json_encode($error);
}

/**
 * Create a simple base64-encoded id_token (not a real JWT for testing)
 */
function createSimpleIdToken($request, $tokenData) {
    global $DB, $CFG;
    
    // Get user from access token
    $storage = new \local_oauth2\moodle_oauth_storage([]);
    $accessTokenInfo = $storage->getAccessToken($tokenData['access_token']);
    
    $user = $DB->get_record('user', ['id' => $accessTokenInfo['user_id']]);
    $clientId = $request->request('client_id');
    $now = time();
    
    // Simple payload (this is for testing - Matrix may not accept it)
    $payload = [
        'iss' => $CFG->wwwroot . '/local/oauth2',
        'sub' => $user->username,
        'aud' => $clientId,
        'exp' => $now + 3600,
        'iat' => $now,
        'name' => fullname($user),
        'email' => $user->email,
        'preferred_username' => $user->username
    ];
    
    // Base64 encode (NOT a real JWT)
    return base64_encode(json_encode($payload));
}
?>
