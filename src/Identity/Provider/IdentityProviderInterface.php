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

/**
 * An identity provider knows how to obtain or request an identity from the client.
 * @package Skyline\Security
 */
interface IdentityProviderInterface
{
    /**
     * The provider must know if an identity was issued by itself or not.
     *
     * @param IdentityInterface $identity
     * @return bool
     */
    public function isProvidedIdentity(IdentityInterface $identity): bool;

    /**
     * Implementation should try to obtain identities from the request.
     * If done, yield them otherwise return null.
     * Throwing exceptions will terminate the identification process and must be catched outside of Skyline Security.
     *
     * @return Generator
     */
    public function yieldIdentities(Request $request): Generator;

    /**
     * In some cases, identities must be installed on the clients browser.
     * The provider can do it in this implementation.
     * Examples are anonymous or remember me identities
     *
     * @param IdentityInterface $identity
     * @param Request $request
     * @param Response $response
     * @return bool
     */
    public function installIdentity(IdentityInterface $identity, Request $request, Response $response);

    /**
     * If identities of this provider may be used by others to install, return true in this implementation
     *
     * @param IdentityInterface $identity
     * @return bool
     */
    public function acceptCommonInstall(IdentityInterface $identity);

    /**
     * It may also be that a provider needs to revoke an identity (logout)
     * This should be done by implementing this method
     *
     * @param IdentityInterface $identity
     * @param Response $response
     * @return bool
     */
    public function uninstallIdentity(IdentityInterface $identity, Response $response);

    /**
     * Probably the provider knows that an identity requires a specific password encoder.
     * In this case it can specify it here.
     *
     * @param IdentityInterface $identity
     * @return null|PasswordEncoderInterface
     */
    public function getSpecificIdentityPasswordEncoder(IdentityInterface $identity): ?PasswordEncoderInterface;
}