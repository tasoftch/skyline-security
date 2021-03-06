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

namespace Skyline\Security\Authentication\Validator;

use Skyline\Security\Authentication\Validator\HashGenerator\HashGeneratorInterface;
use Skyline\Security\Authentication\Validator\Storage\StorageInterface;
use Skyline\Security\Identity\Identity;
use Skyline\Security\Identity\IdentityInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * Subclass this class template to add external storage to this validator
 *
 * @package Skyline\Security\Authentication\Validator
 */
abstract class AbstractStorableValidator extends AbstractValidator
{
    /** @var StorageInterface */
    private $storage;
    /** @var HashGeneratorInterface */
    private $hashGenerator;

    /**
     * AbstractStorableValidator constructor.
     * @param StorageInterface $storage
     */
    public function __construct(StorageInterface $storage, HashGeneratorInterface $hashGenerator)
    {
        $this->storage = $storage;
        $this->hashGenerator = $hashGenerator;
    }


    /**
     * @return StorageInterface
     */
    public function getStorage(): StorageInterface
    {
        return $this->storage;
    }

    /**
     * @return HashGeneratorInterface|null
     */
    public function getHashGenerator(): ?HashGeneratorInterface
    {
        return $this->hashGenerator;
    }

    /**
     * Use this method to obtain hashes to identity identities and requests
     *
     * @param IdentityInterface $identity
     * @param Request $request
     * @return string
     */
    protected function generateIdentificationHash(IdentityInterface $identity, Request $request) {
        return $this->getHashGenerator()->generateHash($identity, $request);
    }
}