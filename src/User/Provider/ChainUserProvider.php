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

namespace Skyline\Security\User\Provider;


use Skyline\Security\Identity\Token\TokenInterface;
use Skyline\Security\User\UserInterface;

class ChainUserProvider implements UserProviderAwareInterface
{
    /** @var UserProviderInterface[] */
    private $providers = [];

    /**
     * ChainUserProvider constructor.
     * @param UserProviderInterface[] $providers
     */
    public function __construct(array $providers = [])
    {
        $this->providers = $providers;
    }

    /**
     * @inheritDoc
     */
    public function getUsernames(): array
    {
        $names = [];
        foreach($this->getProviders() as $provider) {
            if($provider instanceof UserProviderAwareInterface) {
                if($users = $provider->getUsernames()) {
                    array_walk($users , function($A) use (&$names) {
                        if(!in_array($A, $names))
                            $names[] = $A;
                    });
                }
            }
        }
        return $names;
    }

    /**
     * @inheritDoc
     */
    public function loadUserWithToken(TokenInterface $token): ?UserInterface
    {
        foreach($this->getProviders() as $provider) {
            if($u = $provider->loadUserWithToken($token))
                return $u;
        }
        return NULL;
    }

    /**
     * @return UserProviderInterface[]
     */
    public function getProviders(): array
    {
        return $this->providers;
    }

    /**
     * @param UserProviderInterface[] $providers
     * @return static
     */
    public function setProviders(array $providers)
    {
        $this->providers = $providers;
        return $this;
    }

    /**
     * Adds a user provider to the chain
     *
     * @param UserProviderInterface $provider
     * @return static
     */
    public function addProvider(UserProviderInterface $provider) {
        if(!in_array($provider, $this->providers))
            $this->providers[] = $provider;
        return $this;
    }

    /**
     * Removes a user provider from chain
     *
     * @param UserProviderInterface $provider
     * @return static
     */
    public function removeProvider(UserProviderInterface $provider) {
        if(($idx = array_search($provider, $this->providers)) !== false)
            unset($this->providers[$idx]);
        return $this;
    }
}