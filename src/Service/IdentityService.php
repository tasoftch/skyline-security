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

namespace Skyline\Security\Service;


use InvalidArgumentException;
use Skyline\Security\Encoder\PasswordEncoderInterface;
use Skyline\Security\Identity\IdentityInterface;
use Skyline\Security\Identity\Provider\IdentityProviderFactoryInterface;
use Skyline\Security\Identity\Provider\IdentityProviderInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use TASoft\Util\CachedGenerator;

class IdentityService
{
    /** @var IdentityProviderInterface */
    private $provider;
    private $cache = [];

    /**
     * IdentityService constructor.
     * @param IdentityProviderInterface|IdentityProviderFactoryInterface $provider
     */
    public function __construct($provider)
    {
        if($provider instanceof IdentityProviderInterface || $provider instanceof IdentityProviderFactoryInterface)
            $this->provider = $provider;
        else
            throw new InvalidArgumentException("Identity service requires an IdentityProviderInterface or IdentityProviderFactoryInterface as argument");
    }


    /**
     * @return IdentityProviderInterface
     */
    public function getProvider(): IdentityProviderInterface
    {
        if($this->provider instanceof IdentityProviderFactoryInterface)
            $this->provider = $this->provider->getProvider();
        return $this->provider;
    }

    /**
     * Yields all available identities by this request.
     * The identities are cached, so every call yields the same identities for the same request.
     *
     * @param Request $request
     * @return \Generator
     */
    public function yieldIdentities(Request $request) {
        $hash = spl_object_hash($request);
        $generator = $this->cache[$hash] ?? new CachedGenerator( $this->getProvider()->yieldIdentities($request) );
        yield from $generator();
    }

    /**
     * Gets all available identities by this request
     *
     * @param Request $request
     * @return array
     */
    public function getIdentities(Request $request): array {
        return iterator_to_array( $this->yieldIdentities($request) );
    }

    /**
     * Returns the first available identity for this request.
     *
     * @param Request $request
     * @return IdentityInterface|null
     */
    public function getIdentity(Request $request): ?IdentityInterface {
        foreach($this->yieldIdentities($request) as $identity)
            return $identity;
        return NULL;
    }

    /**
     * Gets the first available identity with a minimal reliability.
     *
     * @param Request $request
     * @param int $reliability
     * @return IdentityInterface|null
     */
    public function getIdentityWithReliability(Request $request, int $reliability): ?IdentityInterface {
        /** @var IdentityInterface $identity */
        foreach($this->yieldIdentities($request) as $identity) {
            if($identity->getReliability() >= $reliability)
                return $identity;
        }
        return NULL;
    }

    /**
     * Gets all available identities with minimal reliability.
     * The identities are ordered by reliability, so the most trustful is the first identity in returned array.
     *
     * @param Request $request
     * @param int $reliability
     * @return array
     */
    public function getIdentitiesWithReliability(Request $request, int $reliability): array {
        $list = [];
        /** @var IdentityInterface $identity */
        foreach($this->yieldIdentities($request) as $identity) {
            if($identity->getReliability() >= $reliability)
                $list[] = $identity;
        }

        usort($list, function(IdentityInterface $id1, IdentityInterface $id2) {
            return $id2 <=> $id1;
        });

        return $list;
    }

    /**
     * Forwards an identity installation to the provider
     *
     * @param IdentityInterface $identity
     * @param Request $request
     * @param Response $response
     * @return bool
     */
    public function installIdentity(IdentityInterface $identity, Request $request, Response $response): bool {
        return $this->getProvider()->installIdentity($identity, $request, $response, false) ? true : false;
    }

    /**
     * Forwards an identity revocation to the provider
     *
     * @param IdentityInterface $identity
     * @param Response $response
     * @return bool
     */
    public function uninstallIdentity(IdentityInterface $identity, Response $response): bool {
        return $this->getProvider()->uninstallIdentity($identity, $response, false) ? true : false;
    }

    /**
     * Forwards to provider
     *
     * @param IdentityInterface $identity
     * @return PasswordEncoderInterface|null
     */
    public function getSpecificPasswordEncoder(IdentityInterface $identity): ?PasswordEncoderInterface {
        return $this->getProvider()->getSpecificIdentityPasswordEncoder($identity);
    }

    /**
     * Resets the identity cache.
     */
    public function resetIdentityCache() {
        $this->cache = [];
    }
}