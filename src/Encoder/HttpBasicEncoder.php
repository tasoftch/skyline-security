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


class HttpBasicEncoder extends AbstractPasswordEncoder
{
    /** @var string */
    private $username;

    /** @var string */
    private $realm;

    const OPTION_USER_KEY = 'user';
    const OPTION_REALM_KEY = 'realm';


    public function __construct(string $realm, string $user)
    {
        $this->realm = $realm;
        $this->username = $user;
    }

    public function encodePassword(string $plain, array &$options = []): string
    {
        $this->checkPasswordTooLong($plain);
        $user = $options[static::OPTION_USER_KEY] ?? $this->getUsername();
        $options[static::OPTION_USER_KEY] = $user;

        $salt = $this->getSalt($options);
        if(!isset($options[static::OPTION_REALM_KEY]))
            $options[static::OPTION_REALM_KEY] = $this->getRealm();

        $pass = $this->mergePasswordAndSalt($plain, $salt);
        return base64_encode("$user:$pass");
    }

    /**
     * @return string
     */
    public function getUsername(): string
    {
        return $this->username;
    }

    /**
     * @return string
     */
    public function getRealm(): string
    {
        return $this->realm;
    }

    /**
     * @param string $realm
     */
    public function setRealm(string $realm): void
    {
        $this->realm = $realm;
    }


}