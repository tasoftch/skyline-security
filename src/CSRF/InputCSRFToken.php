<?php

namespace Skyline\Security\CSRF;


class InputCSRFToken extends CSRFToken
{
    public function __toString()
    {
        return sprintf("<input type='hidden' name='%s' value='%s' />\n", htmlspecialchars($this->getId()), htmlspecialchars($this->getValue()));
    }
}