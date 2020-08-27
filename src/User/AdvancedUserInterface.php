<?php
/**
 * Copyright (c) 2018 TASoft Applications, Th. Abplanalp <info@tasoft.ch>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

namespace Skyline\Security\User;


use Skyline\Security\Exception\BlockedUserException;
use Skyline\Security\Exception\HiddenUserException;

interface AdvancedUserInterface
{
	/**
	 * If set, this user can not be changed by any admin tool once created. Also the user itself is not able to change.
	 * The only way is manipulating directly the database.
	 * @var int
	 */
	const OPTION_INTERNAL		= 1<<0;

    /**
     * If set, the user won't be able to login anymore.
     * The authentication service will respond with user not found exception
     * @var int
     * @see HiddenUserException
     */
    const OPTION_HIDDEN         = 1<<1;

    /**
     * If set, the user also won't be able to login anymore.
     * But in this case the authentication service will respond with account blocked exception
     * @var int
     * @see BlockedUserException
     */
    const OPTION_BLOCKED        = 1<<2;

    /**
     * If set, login also is not possible.
     * The authentication service deactivates an account in case of new membership or during password reset process.
     * @var int
     */
    const OPTION_DEACTIVATED    = 1<<3;

    public function getOptions(): int;
}