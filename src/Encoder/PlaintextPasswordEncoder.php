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

/**
 * PlaintextPasswordEncoder does not do any encoding.
 *
 * @author Fabien Potencier <fabien@symfony.com>
 */
class PlaintextPasswordEncoder extends AbstractPasswordEncoder
{
    private $ignorePasswordCase;
    const OPTION_IGNORE_CASE_KEY = 'ignorePasswordCase';

    /**
     * @param bool $ignorePasswordCase Compare password case-insensitive
     */
    public function __construct($ignorePasswordCase = false)
    {
        $this->ignorePasswordCase = $ignorePasswordCase?true:false;
    }

    /**
     * @inheritdoc
     */
    public function encodePassword(string $plain, array &$options = []): string
    {
        $this->checkPasswordTooLong($plain);
        return $plain;
    }

    /**
     * @inheritdoc
     */
    public function isPasswordValid(string $encoded, string $plain, array $options = []): bool
    {
        if($this->isPasswordTooLong($plain))
            return false;

        $password = $this->encodePassword($plain, $options);
        $case = $options[static::OPTION_IGNORE_CASE_KEY] ?? $this->ignorePasswordCase;

        if(!$case) {
            return $this->comparePasswords($encoded, $password);
        }

        return $this->comparePasswords(strtolower($encoded), strtolower($password));
    }
}
