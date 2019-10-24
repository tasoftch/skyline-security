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

namespace Skyline\Security\Identity\Provider;


use Generator;
use Skyline\Security\Encoder\PasswordEncoderInterface;
use Skyline\Security\Identity\IdentityInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class ChainIdentityProvider implements IdentityProviderChainInterface
{
    /** @var IdentityProviderInterface[] */
    private $providers = [];

    /**
     * ChainIdentityProvider constructor.
     * @param IdentityProviderInterface[] $providers
     */
    public function __construct(array $providers = [])
    {
        $this->providers = $providers;
    }

    /**
     * @return IdentityProviderInterface[]
     */
    public function getProviders(): array
    {
        return $this->providers;
    }

    /**
     * @param IdentityProviderInterface[] $providers
     * @return ChainIdentityProvider
     */
    public function setProviders(array $providers): ChainIdentityProvider
    {
        $this->providers = $providers;
        return $this;
    }

    /**
     * @param IdentityProviderInterface|IdentityProviderFactoryInterface $provider
     */
    public function addProvider($provider) {
        if($provider instanceof IdentityProviderFactoryInterface || $provider instanceof IdentityProviderInterface)
            $this->providers[] = $provider;
    }

    /**
     * Removes a provider from chain
     *
     * @param $provider
     */
    public function removeProvider($provider) {
        if(($idx = array_search($provider, $this->providers)) !== false)
            unset($this->providers[$idx]);
    }

    /**
     * Reset chain and remove all providers
     */
    public function removeAllProviders() {
        $this->providers = [];
    }

    /**
     * helper merhod to expand provider factories
     *
     * @param $provider
     * @return IdentityProviderInterface
     */
    private function _solvedProvider($provider): IdentityProviderInterface {
        return $provider instanceof IdentityProviderFactoryInterface ? $provider->getProvider() : $provider;
    }

    public function getProviderByIdentity(IdentityInterface $identity): ?IdentityProviderInterface
    {
        foreach($this->getProviders() as $provider) {
            $provider = $this->_solvedProvider($provider);
            if($provider instanceof IdentityProviderChainInterface) {
                if($p = $provider->getProviderByIdentity($identity))
                    return $p;
            }
            if($provider->isProvidedIdentity($identity))
                return $provider;
        }
        return NULL;
    }

    public function isProvidedIdentity(IdentityInterface $identity): bool
    {
        foreach($this->getProviders() as $provider) {
            $provider = $this->_solvedProvider($provider);
            if($provider->isProvidedIdentity($identity))
                return true;
        }
        return false;
    }

    public function yieldIdentities(Request $request): Generator
    {
        foreach($this->getProviders() as $provider) {
            $provider = $this->_solvedProvider($provider);
            yield from $provider->yieldIdentities($request);
        }
    }

    public function installIdentity(IdentityInterface $identity, Request $request, Response $response)
    {
        if($provider = $this->getProviderByIdentity($identity)) {
            if($provider->acceptCommonInstall($identity)) {
                foreach($this->getProviders() as $prov) {
                    $prov = $this->_solvedProvider($prov);
                    if(!$prov->installIdentity($identity, $request, $response))
                        return false;
                }
                return true;
            } else {
                return $provider->installIdentity($identity, $request, $response);
            }
        }
        return false;
    }

    public function acceptCommonInstall(IdentityInterface $identity)
    {
        if($provider = $this->getProviderByIdentity($identity)) {
            return $provider->acceptCommonInstall($identity);
        }
        return false;
    }

    public function uninstallIdentity(IdentityInterface $identity, Response $response)
    {
        if($provider = $this->getProviderByIdentity($identity)) {
            foreach($this->getProviders() as $identityProvider) {
                $prov = $this->_solvedProvider($identityProvider);

                if(!$prov->uninstallIdentity($identity, $response))
                    return false;
            }
            return true;
        }
        return false;
    }

    public function getSpecificIdentityPasswordEncoder(IdentityInterface $identity): ?PasswordEncoderInterface
    {
        if($provider = $this->getProviderByIdentity($identity)) {
            return $provider->getSpecificIdentityPasswordEncoder($identity);
        }
        return NULL;
    }
}