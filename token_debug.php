<?php
// Debug version of token endpoint
header('Content-Type: application/json');

// Log all incoming data
$debug_data = [
    'method' => $_SERVER['REQUEST_METHOD'],
    'timestamp' => time(),
    'get' => $_GET,
    'post' => $_POST,
    'headers' => getallheaders(),
    'raw_input' => file_get_contents('php://input')
];

// Try to include Moodle config
try {
    require_once(__DIR__ . '/../../config.php');
    $debug_data['moodle_loaded'] = true;
    $debug_data['wwwroot'] = $CFG->wwwroot;
} catch (Exception $e) {
    $debug_data['moodle_error'] = $e->getMessage();
}

// Try to load OAuth2 library
try {
    require_once($CFG->dirroot . '/local/oauth2/vendor/bshaffer/oauth2-server-php/src/OAuth2/Autoloader.php');
    OAuth2\Autoloader::register();
    $debug_data['oauth2_loaded'] = true;
} catch (Exception $e) {
    $debug_data['oauth2_error'] = $e->getMessage();
}

echo json_encode($debug_data, JSON_PRETTY_PRINT);
?>
