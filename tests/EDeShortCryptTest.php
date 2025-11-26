<?php

use \PHPUnit\Framework\Attributes\Test;

class EDeShortCryptTest extends \PHPUnit\Framework\TestCase
{
    const SECRET_KEY = 'really_secret_key_which_is_shared_between_sender_recipient_only';

    #[Test]
    public function Invalid_ThrowsExceptionWithNULLKey()
    {
        $this->expectException(TypeError::class);
        $encrypted = \SPeter\Encryption\EDeShortCrypt::encrypt('secret stuff', null);
    }

    #[Test]
    public function Invalid_CannotDecryptWithoutProperKey()
    {
        $secret = 'This is the secret we want to share. Now you know.';
        $encrypted = \SPeter\Encryption\EDeShortCrypt::encrypt($secret, self::SECRET_KEY);
        $decrypted = \SPeter\Encryption\EDeShortCrypt::decrypt($encrypted, "some other key");
        $this->assertTrue($secret !== $decrypted);
    }

    #[Test]
    public function Invalid_DecryptReturnsFalseIfEncryptionIsBroken()
    {
        $secret = 'This is the secret we want to share. Now you know.';
        $encrypted = \SPeter\Encryption\EDeShortCrypt::encrypt($secret, self::SECRET_KEY);
        $decrypted = \SPeter\Encryption\EDeShortCrypt::decrypt($encrypted.'a', "some other key");
        $this->assertFalse($decrypted);
    }


    #[Test]
    public function Proper_EncryptedTextCanBeDecrypted()
    {
        $secret = 'This is the secret we want to share. Now you know.';
        $encrypted = \SPeter\Encryption\EDeShortCrypt::encrypt($secret, self::SECRET_KEY);
        $decrypted = \SPeter\Encryption\EDeShortCrypt::decrypt($encrypted, self::SECRET_KEY);
        $this->assertTrue($secret === $decrypted);
    }

}