<?php

use \PHPUnit\Framework\Attributes\Test;

class EDeShortCryptTest extends \PHPUnit\Framework\TestCase
{
    const SHORT_SECRET_KEY = 'se'; // 2 byte key
    const SECRET_KEY = 'abcabcabcabc1231abcabcabcabc1231'; // 32 byte key
    const LONG_SECRET_KEY = 'really_secret_key_which_is_shared_between_sender_recipient_only_4'; // 64 byte key

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
        $decrypted = \SPeter\Encryption\EDeShortCrypt::decrypt($encrypted, random_bytes(32));
        $this->assertTrue($secret !== $decrypted);
    }

    #[Test]
    public function Invalid_ThrowsExceptionOnShortKey()
    {
        $this->expectException(\InvalidArgumentException::class);
        \SPeter\Encryption\EDeShortCrypt::encrypt('secret stuff', self::SHORT_SECRET_KEY);
    }


    #[Test]
    public function Proper_EncryptedTextCanBeDecryptedWithLongKey()
    {
        $secret = 'This is the secret we want to share. Now you know.';
        $encrypted = \SPeter\Encryption\EDeShortCrypt::encrypt($secret, self::LONG_SECRET_KEY);
        $decrypted = \SPeter\Encryption\EDeShortCrypt::decrypt($encrypted, self::LONG_SECRET_KEY);
        $this->assertTrue($secret === $decrypted);
    }

    #[Test]
    public function Proper_EncryptedTextCanBeDecrypted()
    {
        $secret = 'This is the secret we want to share. Now you know.';
        $encrypted = \SPeter\Encryption\EDeShortCrypt::encrypt($secret, self::SECRET_KEY);
        $decrypted = \SPeter\Encryption\EDeShortCrypt::decrypt($encrypted, self::SECRET_KEY);
        $this->assertTrue($secret === $decrypted);
    }

    #[Test]
    public function EdgeCase_EmptyStringCanBeEncryptedAndDecrypted()
    {
        $secret = '';
        $encrypted = \SPeter\Encryption\EDeShortCrypt::encrypt($secret, self::SECRET_KEY);
        $decrypted = \SPeter\Encryption\EDeShortCrypt::decrypt($encrypted, self::SECRET_KEY);

        $this->assertNotEmpty($encrypted);
        $this->assertTrue($secret === $decrypted);
    }

    #[Test]
    public function EdgeCase_SpecialCharactersCanBeDecrypted()
    {
        $secret = "Unicode: áéíűőöüú, Null: \0\0\0, Emoji: 🔒✅";
        $encrypted = \SPeter\Encryption\EDeCrypt::encrypt($secret, self::SECRET_KEY);
        $decrypted = \SPeter\Encryption\EDeCrypt::decrypt($encrypted, self::SECRET_KEY);

        $this->assertTrue($secret === $decrypted);
    }

    #[Test]
    public function Tampering_DecryptFailsIfTagIsModified()
    {
        $secret = 'Secret data to test integrity.';
        $encrypted = \SPeter\Encryption\EDeShortCrypt::encrypt($secret, self::SECRET_KEY);
        $binary = base64_decode($encrypted);
        $ivLength = openssl_cipher_iv_length(\SPeter\Encryption\EDeShortCrypt::CIPHER_ALGO);
        $iv = substr($binary, 0, $ivLength);
        $ciphertext = substr($binary, $ivLength + \SPeter\Encryption\EDeShortCrypt::OPENSSL_TAG_LENGTH);
        $modifiedTag = random_bytes(\SPeter\Encryption\EDeShortCrypt::OPENSSL_TAG_LENGTH);
        $modifiedBinary = $iv . $modifiedTag . $ciphertext;
        $modifiedEncrypted = base64_encode($modifiedBinary);
        $decrypted = \SPeter\Encryption\EDeShortCrypt::decrypt($modifiedEncrypted, self::SECRET_KEY);

        $this->assertFalse($decrypted);
    }

    #[Test]
    public function StressTest_Large1MBData()
    {
        $size = 1024 * 1024;
        $secret = openssl_random_pseudo_bytes($size);

        $this->assertEquals($size, strlen($secret));

        $encrypted = \SPeter\Encryption\EDeShortCrypt::encrypt($secret, self::SECRET_KEY);
        $decrypted = \SPeter\Encryption\EDeShortCrypt::decrypt($encrypted, self::SECRET_KEY);

        $this->assertTrue($secret === $decrypted, 'Could not decrypt the 1MB payload');
    }

    #[Test]
    public function StressTest_Large16MBData()
    {
        $size = 1024 * 1024 * 16;
        $secret = openssl_random_pseudo_bytes($size);

        $this->assertEquals($size, strlen($secret));

        $encrypted = \SPeter\Encryption\EDeShortCrypt::encrypt($secret, self::SECRET_KEY);
        $decrypted = \SPeter\Encryption\EDeShortCrypt::decrypt($encrypted, self::SECRET_KEY);

        $this->assertTrue($secret === $decrypted, 'Could not decrypt the 16MB payload');
    }


}