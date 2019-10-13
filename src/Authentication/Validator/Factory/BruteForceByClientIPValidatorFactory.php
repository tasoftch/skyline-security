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


use Skyline\Security\Authentication\Validator\Attempt;
use Skyline\Security\Authentication\Validator\AuthenticationValidatorInterface;
use Skyline\Security\Authentication\Validator\CallbackAttemptValidator;
use Skyline\Security\Authentication\Validator\HashGenerator\RemoteIPHashGenerator;
use Skyline\Security\Authentication\Validator\Storage\AttemptStorage;

class BruteForceByClientIPValidatorFactory implements ValidatorFactoryInterface
{
    /** @var string */
    private $filename;
    /** @var string|null */
    private $userName;
    /** @var string|null */
    private $password;
    /** @var int */
    private $blockedTimeInterval;
    /** @var int */
    private $maximalTrialCount;

    /**
     * BruteForceByClientIPValidatorFactory constructor.
     * @param string $filename
     * @param string|null $userName
     * @param string|null $password
     * @param int $blockedTimeInterval
     * @param int $maximalTrialCount
     */
    public function __construct(string $filename, int $maximalTrialCount = 3, string $userName = NULL, string $password = NULL, int $blockedTimeInterval = 900)
    {
        $this->filename = $filename;
        $this->userName = $userName;
        $this->password = $password;
        $this->blockedTimeInterval = $blockedTimeInterval;
        $this->maximalTrialCount = $maximalTrialCount;
    }


    public function getValidators(): array
    {
        $validator = new CallbackAttemptValidator(function(?Attempt $attempt) {
            if($attempt && $attempt->getTrials() > $this->getMaximalTrialCount())
                return false;
            return true;
        }, new AttemptStorage($this->getFilename(), $this->getUserName(), $this->getPassword()), new RemoteIPHashGenerator(), $this->getBlockedTimeInterval());
        return [$validator];
    }

    /**
     * @return string
     */
    public function getFilename(): string
    {
        return $this->filename;
    }

    /**
     * @return string|null
     */
    public function getUserName(): ?string
    {
        return $this->userName;
    }

    /**
     * @return string|null
     */
    public function getPassword(): ?string
    {
        return $this->password;
    }

    /**
     * @return int
     */
    public function getBlockedTimeInterval(): int
    {
        return $this->blockedTimeInterval;
    }

    /**
     * @param string|null $userName
     * @return BruteForceByClientIPValidatorFactory
     */
    public function setUserName(?string $userName): BruteForceByClientIPValidatorFactory
    {
        $this->userName = $userName;
        return $this;
    }

    /**
     * @param string|null $password
     * @return BruteForceByClientIPValidatorFactory
     */
    public function setPassword(?string $password): BruteForceByClientIPValidatorFactory
    {
        $this->password = $password;
        return $this;
    }

    /**
     * @param int $blockedTimeInterval
     * @return BruteForceByClientIPValidatorFactory
     */
    public function setBlockedTimeInterval(int $blockedTimeInterval): BruteForceByClientIPValidatorFactory
    {
        $this->blockedTimeInterval = $blockedTimeInterval;
        return $this;
    }

    /**
     * @return int
     */
    public function getMaximalTrialCount(): int
    {
        return $this->maximalTrialCount;
    }

    /**
     * @param int $maximalTrialCount
     * @return BruteForceByClientIPValidatorFactory
     */
    public function setMaximalTrialCount(int $maximalTrialCount): BruteForceByClientIPValidatorFactory
    {
        $this->maximalTrialCount = $maximalTrialCount;
        return $this;
    }
}