<?php
    // Define JWT class
    class JWT{
        // Property to store the secret key
        private $key;

        // Constructor to initialize the secret key
        public function __construct($key){
            $this->key = $key;
        }

        // Method to set the secret key
        public function setKey($key){
            $this->key = $key;
        }

        // Method to encode the header of the JWT
        public function encode_header($algo){
            // Define the header with algorithm and type
            $header = [
                'alg' => $algo,
                'type' => 'JWT'
            ];
            // Encode the header and replace spaces with nothing
            $header = base64_encode(str_replace(' ', '', json_encode($header)));
            // Replace characters '+' and '/' with '-' and '_' respectively
            $header = strtr($header, '+/', '-_');
            // Remove padding characters '=' from the end
            return rtrim($header, "=");
        }

        // Method to encode the payload of the JWT
        public function encode_payload($payload){
            // Encode the payload and replace spaces with nothing
            $payload = base64_encode(str_replace(' ', '', json_encode($payload)));
            // Replace characters '+' and '/' with '-' and '_' respectively
            $payload = strtr($payload, '+/', '-_');
            // Remove padding characters '=' from the end
            return rtrim($payload, "=");
        }

        // Method to make a signature for the JWT
        public function makeSignature($payload, $header, $algo){
            // Check if the algorithm is either 'sha256' or 'sha512'
            if($algo === "sha256" || "sha512")
                // If so, create a hash_hmac signature using the specified algorithm,
                // the header and payload concatenated with a dot, and the secret key
                return hash_hmac($algo, $header . "." . $payload, ($this->key), false);
            else
                // If the algorithm is not supported, throw an exception
                throw new Exception("unsupported algorithm");
        }
        
        // Method to sign the JWT
        public function sign($payload, $algo){
            // Encode the payload
            $payload_encode = $this->encode_payload($payload);
            // Encode the header
            $header_encode = $this->encode_header($algo);
            // Make the signature
            $signature = $this->makeSignature($payload_encode, $header_encode, $algo);
            // Check if the signature was made successfully
            if ($signature === false)
                // If not, throw an exception
                throw new Exception("can't make the signature");
            // Return the concatenated header, payload, and signature separated by dots
            return $header_encode.".".$payload_encode.".". $signature;
        }

        public function decode($token){
            $payload = explode(".", $token)[1];
            $payload = strtr($payload, '-_', '+/');
            return base64_decode($payload, false);
        }

        public function verify($token, $algo){
            $split_token = explode(".", $token);
            $header = $split_token[0];
            $payload = $split_token[1];
            $signature = $split_token[2];
            $testingSignature = $this->makeSignature($payload, $header, $algo);
            if ($signature == $testingSignature)
                return $this->decode($token);
            else
                throw new Exception("bad token");
         }
    }

$tmp = new JWT("aymane");
$payload = [
    "name"=> "aymane",
    "id" => 1,
];

$token = $tmp->sign($payload, "sha256");

echo $token;
//$token = "eyJhbGciOiJzaGEyNTYiLCJ0eXBlIjoiSldUIn0=eyJhbGciOiJzaGEyNTYiLCJ0eXBlIjoiSldUIn0.eyJuYW1lIjoiYXltYW5lIiwiaWQiOjF9.2b2abdfc672e5a757a7b0c388919e9ed4710528f56c9b446c4d840e30c364eef";
echo $tmp->verify($token, "sha256");