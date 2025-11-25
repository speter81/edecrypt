<?php

namespace SPeter\Encryption;

class EDeCrypt
{
    const
        CIPHER_ALGO = 'aes-256-gcm',
        OPENSSL_TAG_LENGTH = 16;

    /**
     * Encrypting
     * @param string $plaintext
     * @param string $key
     * @return string
     */
    public static function encrypt(string $plaintext, string $key): string
    {
        $ivLength = openssl_cipher_iv_length(self::CIPHER_ALGO);
        $iv = random_bytes($ivLength);

        $tag = "";

        $ciphertext = openssl_encrypt(
            $plaintext,
            self::CIPHER_ALGO,
            $key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            "",
            self::OPENSSL_TAG_LENGTH
        );

        return base64_encode($iv . $tag . $ciphertext);
    }

    /**
     * Decrypting
     * @param string $encryptedData Base64 encoded data
     * @param string $key
     * @return string|false
     */
    public static function decrypt(string $encryptedData, string $key)
    {
        $binary = base64_decode($encryptedData);
        $ivLength = openssl_cipher_iv_length(self::CIPHER_ALGO);

        if (strlen($binary) < $ivLength + self::OPENSSL_TAG_LENGTH) return false;

        $iv = substr($binary, 0, $ivLength);
        $tag = substr($binary, $ivLength, self::OPENSSL_TAG_LENGTH);
        $ciphertext = substr($binary, $ivLength + self::OPENSSL_TAG_LENGTH);

        return openssl_decrypt(
            $ciphertext,
            self::CIPHER_ALGO,
            $key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag
        );
    }
}
