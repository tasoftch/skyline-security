<?php
/**
 * Copyright (c) 2018 TASoft Applications, Th. Abplanalp <info@tasoft.ch>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

namespace Skyline\Security\Encoder;


use InvalidArgumentException;
use Skyline\Security\Exception\BadCredentialException;

abstract class AbstractPasswordEncoder implements PasswordEncoderInterface
{
    const MAX_PASSWORD_LENGTH = 4096;

    const OPTION_SALT_KEY = 'salt';
    const SKYLINE_DEFAULT_SALT = 'skyline-default-salt';

    /**
     * Demerges a merge password and salt string.
     *
     * @param string $mergedPasswordSalt The merged password and salt string
     *
     * @return array An array where the first element is the password and the second the salt
     */
    protected function demergePasswordAndSalt($mergedPasswordSalt)
    {
        if (empty($mergedPasswordSalt)) {
            return array('', '');
        }

        $password = $mergedPasswordSalt;
        $salt = '';
        $saltBegins = strrpos($mergedPasswordSalt, '{');

        if (false !== $saltBegins && $saltBegins + 1 < strlen($mergedPasswordSalt)) {
            $salt = substr($mergedPasswordSalt, $saltBegins + 1, -1);
            $password = substr($mergedPasswordSalt, 0, $saltBegins);
        }

        return array($password, $salt);
    }

    /**
     * Merges a password and a salt.
     *
     * @param string $password The password to be used
     * @param string $salt     The salt to be used
     *
     * @return string a merged password and salt
     *
     * @throws InvalidArgumentException
     */
    protected function mergePasswordAndSalt($password, $salt)
    {
        if (empty($salt)) {
            return $password;
        }

        if (false !== strrpos($salt, '{') || false !== strrpos($salt, '}')) {
            throw new InvalidArgumentException('Cannot use { or } in salt.');
        }

        return $password.'{'.$salt.'}';
    }

    /**
     * Compares two passwords.
     *
     * This method implements a constant-time algorithm to compare passwords to
     * avoid (remote) timing attacks.
     *
     * @param string $password1 The first password
     * @param string $password2 The second password
     *
     * @return bool true if the two passwords are the same, false otherwise
     */
    protected function comparePasswords($password1, $password2)
    {
        return hash_equals($password1, $password2);
    }

    /**
     * Checks if the password is too long.
     *
     * @param string $password The password to check
     *
     * @return bool true if the password is too long, false otherwise
     */
    protected function isPasswordTooLong($password)
    {
        return strlen($password) > static::MAX_PASSWORD_LENGTH;
    }

    public function isPasswordValid(string $encoded, string $plain, array $options = []): bool
    {
        if(!$this->isPasswordTooLong($plain)) {
            $enc = $this->encodePassword($plain, $options);
            return $this->comparePasswords($encoded, $enc);
        }
        return false;
    }

    /**
     * Internal call to validate password length
     * @param $passwprd
     * @throws BadCredentialException if password is too long
     */
    protected function checkPasswordTooLong($passwprd) {
        if($this->isPasswordTooLong($passwprd)) {
            throw new BadCredentialException("Password is too long");
        }
    }

    protected function getSalt(array &$options = []) {
        if(isset($options[static::OPTION_SALT_KEY]))
            return $options[static::OPTION_SALT_KEY];
        return $options[static::OPTION_SALT_KEY] = static::SKYLINE_DEFAULT_SALT;
    }
}