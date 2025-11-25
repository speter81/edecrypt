<?php

class EDeCryptTest extends \PHPUnit\Framework\TestCase
{
    const SECRET_KEY = 'really_secret_key_which_is_shared_between_sender_recipient_only';

    public function testEncryptedTextCanBeDecrypted()
    {
        $secret = 'This is the secret we want to share. Now you know.';
        $encrypted = \SPeter\Encryption\EDeCrypt::encrypt($secret, self::SECRET_KEY);
        $decrypted = \SPeter\Encryption\EDeCrypt::decrypt($encrypted, self::SECRET_KEY);
        $this->assertTrue($secret === $decrypted);
    }
}