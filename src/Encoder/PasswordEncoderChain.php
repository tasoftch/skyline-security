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


use Skyline\Security\Exception\SecurityException;

class PasswordEncoderChain implements PasswordEncoderInterface
{
    /** @var PasswordEncoderInterface[] */
    private $encoders = [];

    public function encodePassword(string $plain, array &$options = []): string
    {
        if($def = $this->getDefaultEncoder())
            return $def->encodePassword($plain, $options);
        throw new SecurityException("Encoder chain requires at least one encoder", 403);
    }

    public function isPasswordValid(string $encoded, string $plain, array $options = []): bool
    {
        foreach($this->encoders as $encoder) {
            if($encoder->isPasswordValid($encoded, $plain, $options))
                return true;
        }
        return false;
    }

    public function getDefaultEncoder(): ?PasswordEncoderInterface {
        return $this->encoders[0] ?? NULL;
    }

    public function addEncoder(PasswordEncoderInterface $encoder) {
        $this->encoders[] = $encoder;
    }
    public function setEncoders(iterable $encoders) {
        $this->encoders = [];
        foreach($encoders as $encoder)
            $this->addEncoder($encoder);
    }

    public function removeEncoder(PasswordEncoderInterface $encoder) {
        $idx = array_search($encoder, $this->encoders);
        if($idx !== false)
            unset($this->encoders[$idx]);
    }

    public function removeEncoderNamed(string $name) {
        $this->encoders = array_filter($this->encoders, function(PasswordEncoderInterface $encoder) use ($name) {
            if($encoder instanceof EncoderAwareInterface) {
                if($encoder->getEncoderName() == $name)
                    return false;
            }
            return true;
        });
    }

    public function removeAllEncoders() {
        $this->encoders = [];
    }

}