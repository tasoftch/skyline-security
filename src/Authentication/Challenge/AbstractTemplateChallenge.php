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

namespace Skyline\Security\Authentication\Challenge;

use Skyline\Render\Context\RenderContextInterface;
use Skyline\Render\Info\RenderInfoInterface;
use Skyline\Render\Template\TemplateInterface;
use Symfony\Component\HttpFoundation\Response;
use TASoft\Service\ServiceManager;

/**
 * The render challenge assumes, that:
 *  -   challenging the client happens in the SKY_EVENT_PERFORM_ACTION event cycle
 *  -   is done before the action controller performs its action
 *
 * In general it will prepare the render info with a layout and a content to challenge the client.
 *
 * @package Skyline\Security\Authentication\Challenge
 */
abstract class AbstractTemplateChallenge extends AbstractEventChallenge
{
    public function challengeClient(Response $response): bool
    {
        if( parent::challengeClient($response) ) {
            /** @var RenderContextInterface $context */
            $context = ServiceManager::generalServiceManager()->get("renderContext");

            if($info = $context->getRenderInfo()) {
                $info->set( RenderInfoInterface::INFO_TEMPLATE, $this->getMainTemplate() );
                $info->set( RenderInfoInterface::INFO_SUB_TEMPLATES, $this->getChildTemplates() );

                return true;
            }
        }
        return false;
    }

    /**
     * Returns a main template for rendering
     *
     * @return TemplateInterface|string
     */
    abstract protected function getMainTemplate();

    /**
     * Returns a content to render
     *
     * @return TemplateInterface[]|string[]
     */
    abstract protected function getChildTemplates(): array;
}