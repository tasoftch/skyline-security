<?php
/**
 * BSD 3-Clause License
 *
 * Copyright (c) 2019, TASoft Applications
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 *  Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 *  Neither the name of the copyright holder nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

namespace Skyline\Security\Identity;


use Skyline\Security\Identity\Token\TokenInterface;

class Identity implements IdentityInterface
{
    /** @var TokenInterface */
    private $token;
    private $credentials;
    private $options = [];
    private $reliability = 0;



    /**
     * @inheritdoc
     */
    public function getCredentials(): string
    {
        return $this->credentials;
    }

    public function __construct(TokenInterface $token, string $credentials, int $reliability, array $options = [])
    {
        $this->token = $token;
        $this->credentials = $credentials;
        $this->options = $options;
        $this->reliability = $reliability;
    }

    /**
     * @inheritdoc
     */
    public function getOptions(): array
    {
        return $this->options;
    }

    /**
     * @inheritdoc
     */
    public function setOptions(array $options)
    {
        $this->options = $options;
    }

    public function __debugInfo()
    {
        $data = ["Name" => $this->getToken()->getToken(), "Credentials" => str_repeat("•", strlen($this->getCredentials()))];
        $trust = ($state = $this->getReliability()) . " |";

        $state /= 10;

        for($e=0;$e<100;$e++) {
            if($e < $state)
                $trust .= "*";
            else
                $trust .= ".";
        }

        $data["Reliability"] = "$trust|";
        if($opts = $this->getOptions())
            $data["Options"] = $opts;
        return $data;
    }

    /**
     * @return TokenInterface
     */
    public function getToken(): TokenInterface
    {
        return $this->token;
    }

    /**
     * @return int
     */
    public function getReliability(): int
    {
        return $this->reliability;
    }
}