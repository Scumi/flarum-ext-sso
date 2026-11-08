<?php

namespace Maicol07\SSO\Middleware;

use Flarum\Foundation\Config;
use Flarum\Http\RequestUtil;
use Flarum\Settings\SettingsRepositoryInterface;
use Illuminate\Support\Arr;
use Laminas\Diactoros\Response\HtmlResponse;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

class LogoutMiddleware implements MiddlewareInterface
{
    public function __construct(private readonly Config $config, private readonly SettingsRepositoryInterface $settings)
    {
    }

    final public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $actor = RequestUtil::getActor($request);
        $logout_url = resolve('flarum.forum.routes')->getPath('logout');
        $path = $request->getUri()->getPath();
        $cookies = $request->getCookieParams();

        $prefix = $this->settings->get('maicol07-sso.cookies_prefix', 'flarum');

        if (Arr::exists($cookies, "{$prefix}_logout") && !$actor->isGuest()
            && $request->getMethod() === 'GET' && $path !== $logout_url) {
            $base = rtrim((string) $this->config->url(), '/');
            $return = $base . $path;
            if ($query = $request->getUri()->getQuery()) {
                $return .= '?' . $query;
            }
            $action = htmlspecialchars($base . $logout_url . '?' . http_build_query([
                'redirect' => 'false',
                'return' => $return,
            ]), ENT_QUOTES, 'UTF-8');
            $token = htmlspecialchars($request->getAttribute('session')->token(), ENT_QUOTES, 'UTF-8');

            return new HtmlResponse('<!doctype html><html><head><meta charset="utf-8"><title>Logging out</title></head><body>'
                . '<form method="post" action="' . $action . '"><input type="hidden" name="csrfToken" value="' . $token . '">'
                . '<noscript><button type="submit">Log out</button></noscript></form>'
                . '<script>document.forms[0].submit();</script></body></html>', 200, [
                    'Cache-Control' => 'no-store',
                    'Referrer-Policy' => 'no-referrer',
                ]);
        }

        $response = $handler->handle($request);

        // Redirect only after Flarum has finished logout and remember-cookie cleanup.
        if (in_array($request->getAttribute('routeName'), ['logout', 'globalLogout'], true) && !$actor->isGuest()
            && in_array($response->getStatusCode(), [204, 302], true)
            && ($request->getQueryParams()['redirect'] ?? null) !== 'false'
            && $this->settings->get('maicol07-sso.provider_mode') !== '1') {
            $response = $response->withStatus(302)->withHeader('Location', $this->settings->get('maicol07-sso.logout_url'));
        }

        return $response;
    }
}
