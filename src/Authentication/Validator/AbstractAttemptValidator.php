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


use DateTime;
use Skyline\Security\Authentication\Validator\HashGenerator\HashGeneratorInterface;
use Skyline\Security\Authentication\Validator\Storage\AttemptStorage;
use Skyline\Security\Authentication\Validator\Storage\SQLStorageInterface;
use Skyline\Security\Authentication\Validator\Storage\StorageInterface;
use Skyline\Security\Exception\AuthenticationValidatorException;
use Skyline\Security\Exception\FailedAttemptException;
use Skyline\Security\Identity\IdentityInterface;
use Skyline\Security\User\UserInterface;
use Symfony\Component\HttpFoundation\Request;

abstract class AbstractAttemptValidator extends AbstractStorableValidator implements AuthenticationPreValidatorInterface, AuthenticationPostValidatorInterface
{
    /** @var int */
    private $maximalAttemptCount;
    /** @var int */
    private $blockedTimeInterval;

    /**
     * AbstractAttemptValidator constructor.
     * @param StorageInterface $storage
     * @param HashGeneratorInterface $hashGenerator
     * @param int $maximalAttemptCount
     * @param int $blockedTimeInterval
     */
    public function __construct(StorageInterface $storage, HashGeneratorInterface $hashGenerator, int $maximalAttemptCount = 3, int $blockedTimeInterval = 900)
    {
        parent::__construct($storage, $hashGenerator);
        $this->maximalAttemptCount = $maximalAttemptCount;
        $this->blockedTimeInterval = $blockedTimeInterval;
    }

    public function grantAfterAuthentication(IdentityInterface $identity, ?UserInterface $user, Request $request): bool
    {
        $hash = $this->generateIdentificationHash($identity, $request);
        $storage = $this->getStorage();

        if($storage instanceof AttemptStorage) {
            $attempt = $storage->getAttempt( $hash );

            if($user) {
                if($attempt)
                    $storage->clearAttempt($attempt);
            } else {
                if($attempt) {
                    $attempt = new Attempt($hash, new DateTime(), $attempt->getTrials() + 1);
                } else {
                    $attempt = new Attempt($hash, new DateTime(), 1);
                }

                $storage->setAttempt($attempt);
            }
        }
        return false;
    }

    public function grantBeforeAuthentication(IdentityInterface $identity, Request $request): bool
    {
        $hash = $this->generateIdentificationHash($identity, $request);
        $storage = $this->getStorage();

        if($storage instanceof AttemptStorage) {
            $storage->clearAttempts( $this->getValidAttemptLifeTime() );
            $attempt = $storage->getAttempt( $hash );

            if(!$this->validateAttempt($attempt)) {
                $e = new FailedAttemptException("Login got blocked. Too many attempts occures. Please try again later", 403);
                $e->setIdentity($identity);
                $e->setValidator($this);
                $e->setAttempt($attempt);
                throw $e;
            }
        }

        return false;
    }

    /**
     * Implement this method to decide, if an attempt is valid or not.
     *
     * @param Attempt|null $attempt
     * @return bool
     */
    abstract protected function validateAttempt(?Attempt $attempt): bool;

    /**
     * Override this method to specify a different life time for stored attempts.
     * You return a value int seconds, so returning 900 will ignore all attempts older than 15 minutes.
     *
     * @return int
     */
    protected function getValidAttemptLifeTime(): int {
        return $this->getBlockedTimeInterval();
    }

    /**
     * @return int
     */
    public function getMaximalAttemptCount(): int
    {
        return $this->maximalAttemptCount;
    }

    /**
     * @param int $maximalAttemptCount
     */
    public function setMaximalAttemptCount(int $maximalAttemptCount): void
    {
        $this->maximalAttemptCount = $maximalAttemptCount;
    }

    /**
     * @return int
     */
    public function getBlockedTimeInterval(): int
    {
        return $this->blockedTimeInterval;
    }

    /**
     * @param int $blockedTimeInterval
     */
    public function setBlockedTimeInterval(int $blockedTimeInterval): void
    {
        $this->blockedTimeInterval = $blockedTimeInterval;
    }
}