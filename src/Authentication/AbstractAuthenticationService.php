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


use Skyline\Security\Authentication\Validator\AuthenticationPostValidatorInterface;
use Skyline\Security\Authentication\Validator\AuthenticationPreValidatorInterface;
use Skyline\Security\Encoder\EncoderFactoryInterface;
use Skyline\Security\Encoder\PasswordEncoderChain;
use Skyline\Security\Encoder\PasswordEncoderInterface;
use Skyline\Security\Exception\Auth\BlockedUserException;
use Skyline\Security\Exception\Auth\DeactivatedUserException;
use Skyline\Security\Exception\Auth\HiddenUserException;
use Skyline\Security\Exception\Auth\NoIdentityException;
use Skyline\Security\Exception\Auth\WrongPasswordException;
use Skyline\Security\Exception\AuthenticationException;
use Skyline\Security\Exception\AuthenticationValidatorException;
use Skyline\Security\Exception\BadCredentialException;
use Skyline\Security\Exception\UserNotFoundException;
use Skyline\Security\Identity\IdentityInterface;
use Skyline\Security\User\AdvancedUserInterface;
use Skyline\Security\User\Provider\UserProviderInterface;
use Skyline\Security\User\UserInterface;
use SplObjectStorage;
use Symfony\Component\HttpFoundation\Request;
use Throwable;

abstract class AbstractAuthenticationService implements AuthenticationServiceInterface
{
    /** @var SplObjectStorage */
    private $authenticatedUsers;

    /**
     * Same method as authenticateIdentity but will store any failure in $throwable instead of throwing the exception.
     *
     * @param IdentityInterface|null $identity
     * @param Request $request
     * @param Throwable $throwable
     * @param null $specificPasswordEncoder
     * @return UserInterface|null
     *
     * @see AbstractAuthenticationService::authenticateIdentity()
     */
    public function silentAuthenticateIdentity(?IdentityInterface $identity, Request $request, Throwable &$throwable = NULL, $specificPasswordEncoder = NULL): ?UserInterface {
        try {
            return $this->authenticateIdentity($identity, $request, $specificPasswordEncoder);
        } catch (Throwable $exception) {
            $throwable = $exception;
            return NULL;
        }
    }

    /**
     * @inheritDoc
     */
    public function authenticateIdentity(?IdentityInterface $identity, Request $request, $specificPasswordEncoder = NULL): UserInterface
    {
        if(!($identity instanceof IdentityInterface)) {
            throw new NoIdentityException("", 401);
        }

        try {
            $user = NULL;

            try {
                foreach ($this->getBeforeValidators() as $validator) {
                    if($validator->isEnabled() && !$validator->grantBeforeAuthentication($identity, $request)) {
                        $e = new AuthenticationValidatorException("", 401);
                        $e->setValidator($validator);
                        throw $e;
                    }
                }

                if($identity->getReliability() <= $identity::RELIABILITY_ANONYMOUS) {
                    if($user = $this->getAnonymousUser())
                        return $user;

                    throw new NoIdentityException("Anonymous identity is not allowed", 403);
                }

                $user = $this->getUserProvider()->loadUserWithToken( $identity->getToken() );

                if(!($user instanceof UserInterface)) {
                    $e = new UserNotFoundException("", 401);
                    $e->setUsername( $identity->getToken() );
                    throw $e;
                }

                if($user instanceof AdvancedUserInterface) {
                    $options = $user->getOptions();
                    try {
                        if($options & $user::OPTION_BLOCKED)
                            throw new BlockedUserException("", 401);
                        if($options & $user::OPTION_HIDDEN)
                            throw new HiddenUserException("", 401);
                        if($options & $user::OPTION_DEACTIVATED)
                            throw new DeactivatedUserException("", 401);
                    } catch (UserNotFoundException $exception) {
                        /** @var IdentityInterface $identity */
                        $exception->setUsername( $identity->getToken() );
                        throw $exception;
                    }
                }

                $encoder = $this->getPasswordEncoder();

                if($specificPasswordEncoder instanceof PasswordEncoderInterface || $specificPasswordEncoder instanceof EncoderFactoryInterface) {
                    $enc = new PasswordEncoderChain();
                    $enc->addEncoder($specificPasswordEncoder instanceof EncoderFactoryInterface ? $specificPasswordEncoder->getEncoder() : $specificPasswordEncoder);
                    $enc->addEncoder($encoder);
                    $encoder = $enc;
                } elseif($encoder instanceof PasswordEncoderInterface || $encoder instanceof EncoderFactoryInterface) {
                    $encoder = $encoder instanceof EncoderFactoryInterface ? $encoder->getEncoder() : $encoder;
                } else {
                    throw new BadCredentialException("No password encoder specified", 403);
                }


                if(!$encoder->isPasswordValid( $user->getCredentials(), $identity->getCredentials(), $identity->getOptions() )) {
                    $e = new WrongPasswordException("", 401);
                    $e->setUsername($identity->getToken());
                    throw $e;
                }
            } catch (Throwable $exception) {
                throw $exception;
            } finally {
                foreach($this->getAfterValidators() as $validator) {
                    if($validator->isEnabled() && !$validator->grantAfterAuthentication($identity, $user, $request)) {
                        $e = new AuthenticationValidatorException("", 401);
                        $e->setValidator($validator);
                        throw $e;
                    }
                }
            }

            if($user)
                $this->registerIdentity($identity, $user);
            return $user;
        } catch (AuthenticationException $exception) {
            $exception->setIdentity($identity);
            throw $exception;
        }
    }

    /**
     * Internal registration of identity user pair
     *
     * @param IdentityInterface $identity
     * @param UserInterface $user
     */
    protected function registerIdentity(IdentityInterface $identity, UserInterface $user) {
        if(!$this->authenticatedUsers)
            $this->authenticatedUsers = new SplObjectStorage();

        $this->authenticatedUsers[$user] = $identity;
        $this->authenticatedUsers[$identity] = $user;
    }

    /**
     * Gets the user matching the identity, if authenticated
     *
     * @param IdentityInterface $identity
     * @return UserInterface|null
     */
    public function getUserForIdentity(IdentityInterface $identity): ?UserInterface {
        return $this->authenticatedUsers[$identity] ?? NULL;
    }

    /**
     * Gets the identity matching the user, if authenticated
     *
     * @param UserInterface $user
     * @return IdentityInterface|null
     */
    public function getIdentityForUser(UserInterface $user): ?IdentityInterface {
        return $this->authenticatedUsers[$user] ?? NULL;
    }

    /**
     * Clears the authentication (only internal!)
     *
     * @param IdentityInterface|UserInterface $identityOrUser
     */
    public function clearAuthentication($identityOrUser) {
        if($this->authenticatedUsers) {
            $identity = $this->getIdentityForUser($identityOrUser);
            $user = $this->getUserForIdentity($identityOrUser);

            unset($this->authenticatedUsers[$identity]);
            unset($this->authenticatedUsers[$user]);
        }
    }

    /**
     * Returns all validators that must pass before authenticate an identity
     *
     * @return AuthenticationPreValidatorInterface[]
     */
    abstract public function getBeforeValidators(): array;

    /**
     * Returns all validators that must pass after authenticate an identity
     *
     * @return AuthenticationPostValidatorInterface[]
     */
    abstract public function getAfterValidators(): array;

    /**
     * If you want to accept anonymous identities, this method must return a default user for anonymous requests.
     *
     * @return UserInterface|null
     */
    abstract public function getAnonymousUser(): ?UserInterface;

    /**
     * Returns a user provider
     *
     * @return UserProviderInterface
     */
    abstract public function getUserProvider(): UserProviderInterface;

    /**
     * Returns a password encoder to encrypt the identities credentials for comparison
     *
     * @return PasswordEncoderInterface|EncoderFactoryInterface
     */
    abstract public function getPasswordEncoder();
}