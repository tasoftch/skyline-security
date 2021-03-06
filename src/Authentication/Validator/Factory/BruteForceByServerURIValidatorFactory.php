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
use Skyline\Security\Authentication\Validator\CallbackAttemptValidator;
use Skyline\Security\Authentication\Validator\HashGenerator\RequestURIHashGenerator;
use Skyline\Security\Authentication\Validator\Storage\AttemptStorage;

class BruteForceByServerURIValidatorFactory extends BruteForceByClientIPValidatorFactory
{
    public function __construct(string $filename, int $maximalTrialCount = 3, int $blockedTimeInterval = 900, string $tableName = 'URI_ATTEMPT', string $userName = NULL, string $password = NULL)
    {
        parent::__construct($filename, $maximalTrialCount, $blockedTimeInterval, $tableName, $userName, $password);
    }

    public function getValidators(): array
    {
        $validator = new CallbackAttemptValidator(function(?Attempt $attempt) {
            if($attempt && $attempt->getTrials() >= $this->getMaximalTrialCount())
                return false;
            return true;
        }, new AttemptStorage($this->getFilename(), $this->getTableName(), $this->getUserName(), $this->getPassword()), new RequestURIHashGenerator(), $this->getBlockedTimeInterval());
        return [$validator];
    }
}