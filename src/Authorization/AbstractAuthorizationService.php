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

namespace Skyline\Security\Authorization;


use Skyline\Security\Authorization\Voter\VoterInterface;
use Skyline\Security\Exception\AuthorizationException;
use Skyline\Security\User\UserInterface;

abstract class AbstractAuthorizationService implements AuthorizationServiceInterface
{
    const STRATEGY_AFFIRMATIVE = 'affirmative';
    const STRATEGY_CONSENSUS = 'consensus';
    const STRATEGY_UNANIMOUS = 'unanimous';

    /**
     * Must return a valid strategy
     *
     * @return string
     * @see AbstractAuthorizationService::STRATEGY_AFFIRMATIVE
     * @see AbstractAuthorizationService::STRATEGY_CONSENSUS
     * @see AbstractAuthorizationService::STRATEGY_UNANIMOUS
     *
     * or implement another.
     */
    abstract protected function getStrategy(): string;

    /**
     * Called, if all voters were voting abstain.
     *
     * @return bool
     */
    protected function allowIfAbstain(): bool {
        return false;
    }

    /**
     * Called, if equal granted and denied voters
     *
     * @return bool
     */
    protected function allowEqualGrantedAndDenied(): bool {
        return true;
    }

    /**
     * Return all voters to decide.
     *
     * @return VoterInterface[]
     */
    abstract protected function getVoters(): array;

    public function grantAccess(UserInterface $user, $object, array $attributes = []): bool
    {
        $strategyMethod = "grant" . ucfirst($this->getStrategy());
        if(!is_callable([$this, $strategyMethod])) {
            $e = new AuthorizationException("Unsupported strategy decide %s", 403, NULL, $this->getStrategy());
            $e->setUser($user);
            throw $e;
        }

        return $this->{$strategyMethod}($user, $object, $attributes);
    }

    /**
     * Grants access if any voter returns an affirmative response.
     *
     * @param UserInterface $user
     * @param $object
     * @param array $attributes
     * @return bool
     */
    public function grantAffirmative(UserInterface $user, $object, array $attributes = [])
    {
        $deny = 0;
        foreach ($this->getVoters() as $voter) {
            $result = $voter->grantAccess($user, $object, $attributes);
            switch ($result) {
                case VoterInterface::ACCESS_GRANT:
                    return true;

                case VoterInterface::ACCESS_DENIED:
                    ++$deny;

                    break;

                default:
                    break;
            }
        }

        if ($deny > 0) {
            return false;
        }

        return $this->allowIfAbstain();
    }

    /**
     * Grants access if there is consensus of granted against denied responses.
     *
     * Consensus means majority-rule (ignoring abstains) rather than unanimous
     * agreement (ignoring abstains). If you require unanimity, see
     * UnanimousBased.
     *
     * If there were an equal number of grant and deny votes, the decision will
     * be based on the allowIfEqualGrantedDeniedDecisions property value
     * (defaults to true).
     *
     * @param UserInterface $user
     * @param $object
     * @param array $attributes
     * @return bool
     */
    public function grantConsensus(UserInterface $user, $object, array $attributes = [])
    {
        $grant = 0;
        $deny = 0;
        foreach ($this->getVoters() as $voter) {
            $result = $voter->grantAccess($user, $object, $attributes);

            switch ($result) {
                case VoterInterface::ACCESS_GRANT:
                    ++$grant;

                    break;

                case VoterInterface::ACCESS_DENIED:
                    ++$deny;

                    break;
            }
        }

        if ($grant > $deny) {
            return true;
        }

        if ($deny > $grant) {
            return false;
        }

        if ($grant > 0) {
            return $this->allowEqualGrantedAndDenied();
        }

        return $this->allowIfAbstain();
    }

    /**
     * Grants access if only grant (or abstain) votes were received.
     *
     * If all voters abstained from voting, the decision will be based on the
     * allowIfAllAbstainDecisions property value (defaults to false).
     *
     * @param UserInterface $user
     * @param $object
     * @param array $attributes
     * @return bool
     */
    public function grantUnanimous(UserInterface $user, $object, array $attributes = [])
    {
        $grant = 0;
        foreach ($this->getVoters() as $voter) {
            $result = $voter->grantAccess($user, $object, $attributes);

            switch ($result) {
                case VoterInterface::ACCESS_GRANT:
                    ++$grant;

                    break;

                case VoterInterface::ACCESS_DENIED:
                    return false;

                default:
                    break;
            }
        }

        if ($grant > 0) {
            return true;
        }

        return $this->allowIfAbstain();
    }
}