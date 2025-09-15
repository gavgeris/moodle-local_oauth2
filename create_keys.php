<?php
// Create RSA keys for JWT signing
require_once(__DIR__ . '/../../config.php');

try {
    // Check if key already exists
    $existingKey = $DB->get_record('local_oauth2_public_key', ['client_id' => 'global_jwks_key']);
    
    if ($existingKey) {
        echo "Keys already exist!<br>";
        echo "Public key preview: " . substr($existingKey->public_key, 0, 100) . "...<br>";
    } else {
        echo "Generating new RSA key pair...<br>";
        
        // Generate RSA key pair
        $config = array(
            "digest_alg" => "sha256",
            "private_key_bits" => 2048,
            "private_key_type" => OPENSSL_KEYTYPE_RSA,
        );
        
        $resource = openssl_pkey_new($config);
        if (!$resource) {
            throw new Exception('Failed to generate RSA key pair');
        }
        
        // Export private key
        openssl_pkey_export($resource, $privatekey);
        
        // Get public key
        $keydetails = openssl_pkey_get_details($resource);
        $publickey = $keydetails['key'];
        
        // Store in database
        $keyrecord = new stdClass();
        $keyrecord->client_id = 'global_jwks_key';
        $keyrecord->public_key = $publickey;
        $keyrecord->private_key = $privatekey;
        $keyrecord->encryption_algorithm = 'RS256';
        
        $result = $DB->insert_record('local_oauth2_public_key', $keyrecord);
        
        if ($result) {
            echo "✅ Keys generated and stored successfully!<br>";
            echo "Key ID: " . $result . "<br>";
            echo "Public key preview: " . substr($publickey, 0, 100) . "...<br>";
        } else {
            throw new Exception('Failed to store keys in database');
        }
    }
    
    echo "<br><a href='debug_token.php'>Run debug again</a>";
    
} catch (Exception $e) {
    echo "❌ Error: " . $e->getMessage() . "<br>";
    echo "File: " . $e->getFile() . " Line: " . $e->getLine() . "<br>";
}
?>
