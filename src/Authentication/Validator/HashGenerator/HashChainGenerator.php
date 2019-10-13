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

namespace Skyline\Security\Authentication\Validator\HashGenerator;


use Skyline\Security\Identity\IdentityInterface;
use Symfony\Component\HttpFoundation\Request;

class HashChainGenerator implements HashGeneratorInterface
{
    /** @var HashGeneratorInterface[] */
    private $generators = [];

    /**
     * HashChainGenerator constructor.
     * @param HashGeneratorInterface[] $generators
     */
    public function __construct(array $generators = [])
    {
        $this->generators = $generators;
    }


    /**
     * @return HashGeneratorInterface[]
     */
    public function getGenerators(): array
    {
        return $this->generators;
    }

    /**
     * @param HashGeneratorInterface[] $generators
     */
    public function setGenerators(array $generators): void
    {
        $this->generators = $generators;
    }

    public function addGenerator(HashGeneratorInterface $hashGenerator) {
        if(!in_array($hashGenerator, $this->generators))
            $this->generators[] = $hashGenerator;
    }

    public function removeGenerator(HashGeneratorInterface $hashGenerator) {
        if(($idx = array_search($hashGenerator, $this->generators)) !== false)
            unset($this->generators[$idx]);
    }

    public function generateHash(IdentityInterface $identity, Request $request): string
    {
        $hash = "";
        foreach($this->getGenerators() as $generator) {
            $hash .= $generator->generateHash($identity, $request);
        }
        return md5($hash);
    }
}