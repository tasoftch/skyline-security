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

interface IdentityInterface
{
    /**
     * HTTP does not provide a logged in/out state.
     * So any authentication, Skyline Security will set a different cookie than the credentials to store the state.
     * This cookie holds the username. If while creating identities the logged user missmatches, the identification will fail.
     * A logged out cookie hold the value "-"
     */
    const LOGGED_COOKIE_NAME = '_skyline_logged';

    const RELIABILITY_MINIMUM       = 0;
    const RELIABILITY_MAXIMUM       = 1000;

    const RELIABILITY_ANONYMOUS     = 10;
    const RELIABILITY_HTTP          = 100;

    const RELIABILITY_REMEMBER_ME   = 150;
    const RELIABILITY_SESSION       = 200;

    const RELIABILITY_HTML_FORM     = 500;

    /**
     * The identification token
     * @return TokenInterface
     */
    public function getToken(): TokenInterface;

    /**
     * The hashed password.
     * @return string
     */
    public function getCredentials(): string;

    /**
     * Options to specify the identity
     * @return array
     */
    public function getOptions(): array;

    /**
     * Options to specify the identity
     *
     * @param array $options
     * @return void
     */
    public function setOptions(array $options);

    /**
     * @return int
     */
    public function getReliability(): int;
}