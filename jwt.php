<?php
    class JWT{
        private $key;

        public function __construct($key){
            $this->key = $key;
        }

        public function setKey($key){
            $this->key = $key;
        }

        public function encode_header($algo){
            $header = [
                'alg' => $algo,
                'type' => 'JWT'
            ];
            $header = base64_encode(str_replace(' ', '', json_encode($header)));
            $header = strtr($header, '+/', '-_');
            return rtrim($header, "=");
        }

        public function encode_payload($payload){
            $payload = base64_encode(str_replace(' ', '', json_encode($payload)));
            $payload = strtr($payload, '+/', '-_');
            return rtrim($payload, "=");
        }

        public function makeSignature($payload, $header, $algo){
            if($algo === "sha256" || "sha512")
                return hash_hmac($algo, $header . "." . $payload, ($this->key), false);
            else
                throw new Exception("unsupported algorithm");
        }
        public function sign($payload, $algo){
            $payload_encode = $this->encode_payload($payload);
            $header_encode = $this->encode_header($algo);
            $signature = $this->makeSignature($payload_encode, $header_encode, $algo);
            if ($signature === false)
                throw new Exception("can't make the signature");
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
//$token = "eyJhbGciOiJzaGEyNTYiLCJ0eXBlIjoiSldUIn0=eyJhbGciOiJzaGEyNTYiLCJ0eXBlIjoiSldUIn0.eyJuYW1lIjoiYXltYW5lIiwiaWQiOjF9.2b2abdfc672e5a757a7b0c388919e9ed4710528f56c9b446c4d840e30c364eef";
echo $tmp->verify($token, "sha256");