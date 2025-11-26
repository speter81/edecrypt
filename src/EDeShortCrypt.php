<?php

namespace SPeter\Encryption;

class EDeShortCrypt
{
   const
        CIPHER_ALGO = 'aes-256-gcm',
        OPENSSL_TAG_LENGTH = 16;

    private static function base64UrlEncode($data):string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    private static function base64UrlDecode($data):string
    {
        return base64_decode(str_pad(strtr($data, '-_', '+/'), strlen($data) % 4, '=', STR_PAD_RIGHT));
    }

    /**
     * Encrypting
     * @param string $plaintext
     * @param string $key
     * @return string
     */
    public static function encrypt(string $plaintext, string $key): string
    {
        $compressed = gzcompress($plaintext, 9);
        $ivLength = openssl_cipher_iv_length(self::CIPHER_ALGO);
        $iv = random_bytes($ivLength);

        $tag = "";

        $ciphertext = openssl_encrypt(
            $compressed,
            self::CIPHER_ALGO,
            $key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            "",
            self::OPENSSL_TAG_LENGTH
        );

        return self::Base64UrlEncode($iv . $tag . $ciphertext);
    }


   /**
     * Decrypting
     * Returns decoded string on success, false if there was an error
     * @param string $encryptedData Base64 encoded data
     * @param string $key
     * @return string|false
     */
    public static function decrypt(string $encryptedData, string $key): string|bool
    {
        $binary = self::Base64UrlDecode($encryptedData);
        $ivLength = openssl_cipher_iv_length(self::CIPHER_ALGO);

        if (strlen($binary) < $ivLength + self::OPENSSL_TAG_LENGTH) return false;

        $iv = substr($binary, 0, $ivLength);
        $tag = substr($binary, $ivLength, self::OPENSSL_TAG_LENGTH);
        $ciphertext = substr($binary, $ivLength + self::OPENSSL_TAG_LENGTH);

        $decryptedCompressed = openssl_decrypt(
            $ciphertext,
            self::CIPHER_ALGO,
            $key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag
        );

        if ($decryptedCompressed === false) return false;

        return gzuncompress($decryptedCompressed);
    }

}
