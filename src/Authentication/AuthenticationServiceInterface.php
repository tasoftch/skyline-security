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


use Skyline\Security\Encoder\EncoderFactoryInterface;
use Skyline\Security\Encoder\PasswordEncoderInterface;
use Skyline\Security\Exception\Auth\BlockedUserException;
use Skyline\Security\Exception\Auth\DeactivatedUserException;
use Skyline\Security\Exception\Auth\HiddenUserException;
use Skyline\Security\Exception\Auth\NoIdentityException;
use Skyline\Security\Exception\Auth\WrongPasswordException;
use Skyline\Security\Exception\AuthenticationValidatorException;
use Skyline\Security\Exception\BadCredentialException;
use Skyline\Security\Exception\UserNotFoundException;
use Skyline\Security\Identity\IdentityInterface;
use Skyline\Security\User\UserInterface;
use Symfony\Component\HttpFoundation\Request;
use Throwable;

interface AuthenticationServiceInterface
{
    /**
     * This method authenticates an identity. So it will try to find a user that matches to the identity's token and then verify the identity's credential.
     *
     * @param IdentityInterface|null $identity      The identity to authenticate
     * @param Request $request                      The original request, used for pre and post validation
     * @param PasswordEncoderInterface|EncoderFactoryInterface|null $specificPasswordEncoder        Specific password encoder for this identity
     * @return UserInterface
     *
     * @throws Throwable                            Anything went wrong while authentication
     * @throws NoIdentityException                  Thrown if no identity specified (code 401) or no anonymous user is set for identity (code 403)
     * @throws AuthenticationValidatorException     Thrown if a pre validator or post validator denies the authentication
     * @throws UserNotFoundException                Thrown if no user could be found for the requested identity token
     *
     * @throws BlockedUserException                 Thrown if the user is blocked by an administrator
     * @throws HiddenUserException                  Thrown if the user is hidden (should be handled as if it does not exist)
     * @throws DeactivatedUserException             Thrown if the user is deactivated
     *
     * @throws BadCredentialException               Thrown if the credentials could not be encrypted for comparison
     * @throws WrongPasswordException               Thrown if the user's credential does not match to the identity's credentials
     */
    public function authenticateIdentity(?IdentityInterface $identity, Request $request, $specificPasswordEncoder = NULL): UserInterface;
}