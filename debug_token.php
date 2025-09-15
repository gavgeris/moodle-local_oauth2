<?php
// Debug version with visible errors
error_reporting(E_ALL);
ini_set('display_errors', 1);
ini_set('log_errors', 1);

echo "Starting debug...<br>";

try {
    require_once(__DIR__ . '/../../config.php');
    echo "Moodle config loaded...<br>";
    
    // Test basic functionality
    echo "Testing database connection...<br>";
    $test = $DB->get_record('user', ['id' => 2]);
    echo "Database OK...<br>";
    
    // Test OAuth2 library loading
    echo "Loading OAuth2 library...<br>";
    require_once($CFG->dirroot . '/local/oauth2/vendor/bshaffer/oauth2-server-php/src/OAuth2/Autoloader.php');
    OAuth2\Autoloader::register();
    echo "OAuth2 library loaded...<br>";
    
    // Test storage
    echo "Testing storage...<br>";
    $storage = new \local_oauth2\moodle_oauth_storage([]);
    echo "Storage created...<br>";
    
    // Test key loading
    echo "Testing private key...<br>";
    $keyRecord = $DB->get_record('local_oauth2_public_key', ['client_id' => 'global_jwks_key']);
    if ($keyRecord) {
        echo "Private key found in database...<br>";
    } else {
        echo "No private key in database...<br>";
    }
    
    // Test OpenSSL
    echo "Testing OpenSSL...<br>";
    if (function_exists('openssl_sign')) {
        echo "OpenSSL available...<br>";
    } else {
        echo "OpenSSL NOT available...<br>";
    }
    
    echo "All tests passed!<br>";
    
} catch (Exception $e) {
    echo "<h2>ERROR:</h2>";
    echo "<pre>";
    echo "Message: " . $e->getMessage() . "\n";
    echo "File: " . $e->getFile() . "\n";
    echo "Line: " . $e->getLine() . "\n";
    echo "Trace:\n" . $e->getTraceAsString();
    echo "</pre>";
}
?>
