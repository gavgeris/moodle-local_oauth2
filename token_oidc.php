<?php
// Simple JWT solution without complex signing
use core\session\manager;
use OAuth2\Request;

require_once(__DIR__ . '/../../config.php');

manager::write_close();

try {
    // Load OAuth2 library and handle normal token request
    require_once($CFG->dirroot . '/local/oauth2/vendor/bshaffer/oauth2-server-php/src/OAuth2/Autoloader.php');
    OAuth2\Autoloader::register();

    $server = local_oauth2\utils::get_oauth_server();
    $request = Request::createFromGlobals();
    $response = new \OAuth2\Response();

    $tokenResponse = $server->handleTokenRequest($request, $response);

    if ($tokenResponse->getStatusCode() == 200) {
        $tokenData = json_decode($tokenResponse->getContent(), true);

        // Add simple id_token for OpenID Connect
        $scope = $request->request('scope', '');
        if (strpos($scope, 'openid') !== false) {
            $tokenData['id_token'] = createSimpleJWT($request, $tokenData);
        }

        header('Content-Type: application/json');
        echo json_encode($tokenData);
    } else {
        $tokenResponse->send();
    }

} catch (Exception $e) {
    header('HTTP/1.1 500 Internal Server Error');
    header('Content-Type: application/json');
    echo json_encode(['error' => 'server_error', 'error_description' => $e->getMessage()]);
}

function createSimpleJWT($request, $tokenData) {
    global $DB, $CFG;

    // Get user info
    $storage = new \local_oauth2\moodle_oauth_storage([]);
    $accessTokenInfo = $storage->getAccessToken($tokenData['access_token']);
    $user = $DB->get_record('user', ['id' => $accessTokenInfo['user_id']]);

    // Create simple unsigned JWT for testing
    $header = ['typ' => 'JWT', 'alg' => 'none'];
    $payload = [
        'iss' => $CFG->wwwroot . '/local/oauth2',
        'sub' => $user->username,
        'aud' => $request->request('client_id'),
        'exp' => time() + 3600,
        'iat' => time(),
        'name' => fullname($user),
        'email' => $user->email,
        'preferred_username' => $user->username
    ];

    $headerEncoded = base64urlEncode(json_encode($header));
    $payloadEncoded = base64urlEncode(json_encode($payload));

    return $headerEncoded . '.' . $payloadEncoded . '.';
}

function base64urlEncode($data) {
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}
?>