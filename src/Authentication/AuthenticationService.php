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

namespace Skyline\Security\Authentication;

use InvalidArgumentException;
use Skyline\Security\Authentication\Validator\AuthenticationPostValidatorInterface;
use Skyline\Security\Authentication\Validator\AuthenticationPreValidatorInterface;
use Skyline\Security\Authentication\Validator\AuthenticationValidatorInterface;
use Skyline\Security\Authentication\Validator\Factory\ValidatorFactoryInterface;
use Skyline\Security\Encoder\EncoderFactoryInterface;
use Skyline\Security\Encoder\PasswordEncoderInterface;
use Skyline\Security\User\Provider\UserProviderInterface;
use Skyline\Security\User\UserInterface;

class AuthenticationService extends AbstractAuthenticationService
{
    /** @var UserProviderInterface */
    private $userProvider;
    /** @var UserInterface|null */
    private $anonymousUser;
    /** @var AuthenticationPreValidatorInterface[]  */
    private $beforeValidators = [];
    /** @var AuthenticationPostValidatorInterface[] */
    private $afterValidators = [];
    /** @var PasswordEncoderInterface|EncoderFactoryInterface */
    private $passwordEncoder;

    /**
     * AuthenticationService constructor.
     * @param UserProviderInterface $userProvider
     * @param $passwordEncoder
     * @param iterable $validators
     */
    public function __construct(UserProviderInterface $userProvider, $passwordEncoder, iterable $validators = [])
    {
        $this->userProvider = $userProvider;
        if($passwordEncoder instanceof PasswordEncoderInterface || $passwordEncoder instanceof EncoderFactoryInterface)
            $this->passwordEncoder = $passwordEncoder;
        else
            throw new InvalidArgumentException("Password Encoder argument must be an object of class PasswordEncoderInterface or EncoderFactoryInterface");

        foreach ($validators as $validator) {
            $this->addValidator($validator);
        }
    }

    /**
     * @inheritDoc
     */
    public function getUserProvider(): UserProviderInterface
    {
        return $this->userProvider;
    }

    /**
     * @inheritDoc
     */
    public function getAnonymousUser(): ?UserInterface
    {
        return $this->anonymousUser;
    }

    /**
     * @param UserInterface|null $anonymousUser
     */
    public function setAnonymousUser(?UserInterface $anonymousUser): void
    {
        $this->anonymousUser = $anonymousUser;
    }

    /**
     * Adds a validator
     *
     * @param AuthenticationValidatorInterface|ValidatorFactoryInterface $validator
     * @return static
     */
    public function addValidator($validator) {
        $addValidator = function($v) {
            if($v instanceof AuthenticationPreValidatorInterface && !in_array($v, $this->beforeValidators))
                $this->beforeValidators[] = $v;
            if($v instanceof AuthenticationPostValidatorInterface && !in_array($v, $this->afterValidators))
                $this->afterValidators[] = $v;
        };

        if($validator instanceof ValidatorFactoryInterface) {
            foreach($validator->getValidators() as $v)
                $addValidator($v);

        } else {
            $addValidator($validator);
        }

        return $this;
    }

    /**
     * Removes a validator
     *
     * @param AuthenticationPreValidatorInterface|AuthenticationPostValidatorInterface $validator
     * @return static
     */
    public function removeValidator($validator) {
        if(($idx = array_search($validator, $this->beforeValidators)) !== false)
            unset($this->beforeValidators[$idx]);
        if(($idx = array_search($validator, $this->afterValidators)) !== false)
            unset($this->afterValidators[$idx]);
        return $this;
    }

    /**
     * @inheritDoc
     */
    public function getBeforeValidators(): array
    {
        return $this->beforeValidators;
    }

    /**
     * @inheritDoc
     */
    public function getAfterValidators(): array
    {
        return $this->afterValidators;
    }

    /**
     * @inheritDoc
     */
    public function getPasswordEncoder()
    {
        return $this->passwordEncoder instanceof EncoderFactoryInterface ? $this->passwordEncoder->getEncoder() : $this->passwordEncoder;
    }
}