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

namespace Skyline\Security\Authentication\Validator\Factory;


use Skyline\Security\Authentication\Validator\AbstractAttemptValidator;
use Skyline\Security\Authentication\Validator\Attempt;
use Skyline\Security\Authentication\Validator\HashGenerator\TokenHashGenerator;
use Skyline\Security\Authentication\Validator\Storage\AttemptStorage;
use Skyline\Security\Exception\AutoLogoutException;
use Skyline\Security\Exception\FailedAttemptException;
use Skyline\Security\Identity\IdentityInterface;
use Symfony\Component\HttpFoundation\Request;
use Skyline\Security\User\UserInterface;

class AutoLogoutValidatorFactory extends BruteForceByClientIPValidatorFactory
{
    public function __construct(string $filename, int $maximalInactiveTimeInterval = 900, string $tableName = 'AL_ATTEMPT', string $userName = NULL, string $password = NULL)
    {
        parent::__construct($filename, 0, $maximalInactiveTimeInterval, $tableName, $userName, $password);
    }

    /**
     *
     * @return int
     */
    public function getMaximalInactiveTimeInterval(): int {
        return $this->getBlockedTimeInterval();
    }

    public function getValidators(): array
    {
        return [
            new class(
                new AttemptStorage(
                    $this->getFilename(),
                    $this->getTableName(),
                    $this->getUserName(),
                    $this->getPassword()
                ),
                new TokenHashGenerator(),
                $this->getMaximalInactiveTimeInterval()
            ) extends AbstractAttemptValidator {

                protected function validateAttempt(?Attempt $attempt): bool
                {
                    if($attempt) {
                        $ts = $attempt->getDate()->getTimestamp();
                        return time() - $this->getBlockedTimeInterval() >= $ts ? false : true;
                    }
                    return true;
                }

                public function grantBeforeAuthentication(IdentityInterface $identity, Request $request): bool
                {
                    try {
                    	if($identity->getReliability() <= IdentityInterface::RELIABILITY_SESSION)
                        	return parent::grantBeforeAuthentication($identity, $request);
                    	return true;
                    } catch (FailedAttemptException $exception) {
                        $e = new AutoLogoutException("Session limit reached", 401);
                        $e->setValidator($this);
                        $e->setIdentity($identity);
                        throw $e;
                    }
                }

                public function grantAfterAuthentication(IdentityInterface $identity, ?UserInterface $user, Request $request): bool
                {
                    // Always register attempts
                    return parent::grantAfterAuthentication($identity, NULL, $request);
                }

                protected function clearAttempts(AttemptStorage $storage)
                {
                    // Do not clear attempts!
                }
            }
        ];
    }
}