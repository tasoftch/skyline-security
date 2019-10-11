<?php

/*
 * This file is part of the Symfony package.
 *
 * (c) Fabien Potencier <fabien@symfony.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Skyline\Security\Encoder;

use InvalidArgumentException;
use Skyline\Security\Exception\BadCredentialException;

/**
 * @author Elnur Abdurrakhimov <elnur@elnur.pro>
 * @author Terje Bråten <terje@braten.be>
 */
class BCryptPasswordEncoder extends AbstractPasswordEncoder
{
    const MAX_PASSWORD_LENGTH = 72;
    const OPTION_COST_KEY = 'cost';

    private $cost;

    /**
     * @param int $cost The algorithmic cost that should be used
     *
     * @throws \RuntimeException         When no BCrypt encoder is available
     * @throws InvalidArgumentException if cost is out of range
     */
    public function __construct(int $cost)
    {
        if ($cost < 4 || $cost > 31) {
            throw new InvalidArgumentException('Cost must be in the range of 4-31.');
        }

        $this->cost = $cost;
    }

    /**
     * Encodes the raw password.
     *
     * It doesn't work with PHP versions lower than 5.3.7, since
     * the password compat library uses CRYPT_BLOWFISH hash type with
     * the "$2y$" salt prefix (which is not available in the early PHP versions).
     *
     * @see https://github.com/ircmaxell/password_compat/issues/10#issuecomment-11203833
     *
     * It is almost best to **not** pass a salt and let PHP generate one for you.
     *
     * @param string $raw  The password to encode
     * @param string $salt The salt
     *
     * @return string The encoded password
     *
     * @throws BadCredentialException when the given password is too long
     *
     * @see http://lxr.php.net/xref/PHP_5_5/ext/standard/password.c#111
     */
    public function encodePassword(string $raw, array &$options = []): string
    {
        $this->checkPasswordTooLong($raw);
        $optc = $options[static::OPTION_COST_KEY] ?? 0;

        if($optc < 4 || $optc > 31)
            $options[static::OPTION_COST_KEY] = $this->cost;

        return password_hash($raw, PASSWORD_BCRYPT, $options);
    }

    /**
     * @inheritdoc
     */
    public function isPasswordValid(string $encoded, string $plain, array $options = []): bool
    {
        return !$this->isPasswordTooLong($plain) && password_verify($plain, $encoded);
    }
}
