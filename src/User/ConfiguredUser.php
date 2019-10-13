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

namespace Skyline\Security\User;


use ArrayAccess;
use InvalidArgumentException;

class ConfiguredUser extends AdvancedUser
{
    const USERNAME_KEY = 'username';
    const CREDENTIALS_KEY = 'credentials';
    const OPTIONS_KEY = 'options';

    /**
     * ConfiguredUser constructor.
     * @param array|ArrayAccess $data
     * @param array $roles
     */
    public function __construct($data, array $roles = [])
    {
        $username = $data[ static::USERNAME_KEY ] ?? NULL;
        $credentials = $data[ static::CREDENTIALS_KEY ] ?? NULL;

        if(!$username || !$credentials)
            throw new InvalidArgumentException("Data record for configured users must contain a username key and a credentials key", 403);

        parent::__construct($username, $credentials, $roles, $data[ static::OPTIONS_KEY ] ?? 0);

        unset($data[static::USERNAME_KEY]);
        unset($data[static::CREDENTIALS_KEY]);

        $this->loadFurtherData($data);
    }

    /**
     * Override this method to adjust further user properties from record.
     *
     * @param $data
     */
    protected function loadFurtherData($data) {
    }
}