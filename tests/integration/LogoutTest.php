<?php

namespace Maicol07\SSO\Tests;

use Dflydev\FigCookies\FigResponseCookies;
use Flarum\Extend;
use Flarum\Http\AccessToken;
use Flarum\Http\RequestUtil;
use Flarum\Testing\integration\RetrievesAuthorizedUsers;
use Flarum\Testing\integration\TestCase;
use Flarum\User\Event\LoggedOut;
use Flarum\User\User;
use Laminas\Diactoros\Response\JsonResponse;
use PHPUnit\Framework\Attributes\DataProvider;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

class ActorProbe implements RequestHandlerInterface
{
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        return new JsonResponse(['guest' => RequestUtil::getActor($request)->isGuest()]);
    }
}

class LogoutTest extends TestCase
{
    use RetrievesAuthorizedUsers;

    private int $logoutEvents = 0;

    protected function request(string $method, string $path, array $options = []): ServerRequestInterface
    {
        $basePath = parse_url($this->config['url'] ?? '', PHP_URL_PATH) ?: '';

        return parent::request($method, $basePath . $path, $options);
    }

    protected function setUp(): void
    {
        $this->extension('maicol07-sso');
        $this->setting('maicol07-sso.logout_url', 'https://bronkhausen.example/logout');
        $this->extend(
            (new Extend\Routes('forum'))->get('/sso-test', 'sso-test', ActorProbe::class),
            (new Extend\Event())->listen(LoggedOut::class, function () {
                $this->logoutEvents++;
            })
        );
        $this->prepareDatabase([User::class => [$this->normalUser()]]);
    }

    private function login(bool $remember = false): ResponseInterface
    {
        $initial = $this->send($this->request('GET', '/sso-test'));
        $this->assertSame(200, $initial->getStatusCode());
        $response = $this->send(
            $this->request('POST', '/login', ['cookiesFrom' => $initial, 'json' => [
                'identification' => 'normal',
                'password' => 'too-obscure',
                'remember' => $remember,
            ]])->withHeader('X-CSRF-Token', $initial->getHeaderLine('X-CSRF-Token'))
        );
        $this->assertSame(200, $response->getStatusCode(), (string) $response->getBody());

        return $response;
    }

    public static function sessions(): array
    {
        return [[false, '', 'flarum'], [true, '', 'flarum'], [true, '/forum', 'bronkhausen'], [true, '', 'flarum', true]];
    }

    #[DataProvider('sessions')]
    public function test_cookie_logout_uses_post_and_cannot_restore_session(bool $remember, string $basePath, string $prefix, bool $rememberOnly = false): void
    {
        $this->config('url', 'http://localhost' . $basePath);
        $this->config('cookie.name', $prefix);
        $this->setting('maicol07-sso.cookies_prefix', $prefix);
        $login = $this->login($remember);
        $accessToken = json_decode((string) $login->getBody(), true)['token'];
        $oldCookies = $this->request('GET', '/', ['cookiesFrom' => $login])->getCookieParams();
        // The provider removes token/remember cookies but leaves the forum session.
        $cookies = $oldCookies;
        unset($cookies[$prefix . '_remember'], $cookies[$prefix . '_token']);
        if ($rememberOnly) {
            $cookies = [$prefix . '_remember' => $oldCookies[$prefix . '_remember']];
        }
        $cookies[$prefix . '_logout'] = '1';

        $form = $this->send($this->request('GET', '/sso-test?q=%22%3Cscript%3E')->withCookieParams($cookies));
        $this->assertSame(200, $form->getStatusCode());
        $this->assertSame('no-store', $form->getHeaderLine('Cache-Control'));
        $document = new \DOMDocument();
        $document->loadHTML((string) $form->getBody());
        $element = $document->getElementsByTagName('form')->item(0);
        $this->assertSame('post', $element->getAttribute('method'));
        $action = $element->getAttribute('action');
        $this->assertSame('http://localhost' . $basePath . '/logout', strtok($action, '?'));
        $csrfToken = $document->getElementsByTagName('input')->item(0)->getAttribute('value');
        $this->assertSame($form->getHeaderLine('X-CSRF-Token'), $csrfToken);
        $this->assertStringNotContainsString($csrfToken, $action);
        $this->assertStringContainsString('document.forms[0].submit()', (string) $form->getBody());
        $this->assertNotNull(AccessToken::whereToken($accessToken)->first());
        parse_str(parse_url($action, PHP_URL_QUERY), $query);

        $post = $this->request('POST', '/logout', ['cookiesFrom' => $form])->withQueryParams($query);
        $this->assertSame(400, $this->send($post)->getStatusCode());
        $logout = $this->send($post->withParsedBody(['csrfToken' => $csrfToken]));
        $this->assertSame(302, $logout->getStatusCode());
        $this->assertSame('http://localhost' . $basePath . '/sso-test?q=%22%3Cscript%3E', $logout->getHeaderLine('Location'));
        $this->assertNull(AccessToken::whereToken($accessToken)->first());
        $this->assertSame(1, $this->logoutEvents);
        $this->assertStringContainsString($prefix . '_remember=', implode(';', $logout->getHeader('Set-Cookie')));
        $this->assertLessThan(time(), FigResponseCookies::get($logout, $prefix . '_remember')->getExpires());

        // Neither the new session nor replaying the old session/remember cookies can log in again.
        foreach ([$this->request('GET', '/sso-test', ['cookiesFrom' => $logout])->getCookieParams(), $oldCookies] as $revisit) {
            $revisit[$prefix . '_logout'] = '1';
            $response = $this->send($this->request('GET', '/sso-test')->withCookieParams($revisit));
            $this->assertSame(['guest' => true], json_decode((string) $response->getBody(), true));
        }
    }

    public function test_guest_with_logout_cookie_passes_through(): void
    {
        $response = $this->send($this->request('GET', '/sso-test')->withCookieParams(['flarum_logout' => '1']));
        $this->assertSame(['guest' => true], json_decode((string) $response->getBody(), true));
        $this->assertSame(0, $this->logoutEvents);
    }

    public static function logoutRoutes(): array
    {
        return [['/logout'], ['/global-logout']];
    }

    #[DataProvider('logoutRoutes')]
    public function test_ordinary_forum_logout_redirects_after_cleanup(string $route): void
    {
        $login = $this->login(true);
        $token = json_decode((string) $login->getBody(), true)['token'];
        $response = $this->send($this->request('POST', $route, ['cookiesFrom' => $login])
            ->withParsedBody(['csrfToken' => $login->getHeaderLine('X-CSRF-Token')]));
        $this->assertSame('https://bronkhausen.example/logout', $response->getHeaderLine('Location'));
        $this->assertNull(AccessToken::whereToken($token)->first());
        $this->assertSame(1, $this->logoutEvents);
        $this->assertStringContainsString('flarum_remember=', implode(';', $response->getHeader('Set-Cookie')));
        $revisit = $this->send($this->request('GET', '/sso-test', ['cookiesFrom' => $response]));
        $this->assertSame(['guest' => true], json_decode((string) $revisit->getBody(), true));
    }

    public function test_provider_logout_keeps_flarum_redirect(): void
    {
        $this->setting('maicol07-sso.provider_mode', '1');
        $login = $this->login();
        $response = $this->send($this->request('POST', '/logout', ['cookiesFrom' => $login])
            ->withParsedBody(['csrfToken' => $login->getHeaderLine('X-CSRF-Token')]));
        $this->assertSame('http://localhost', $response->getHeaderLine('Location'));
    }

    public function test_get_logout_still_requires_confirmation(): void
    {
        $login = $this->login();
        $token = json_decode((string) $login->getBody(), true)['token'];
        $response = $this->send($this->request('GET', '/logout', ['cookiesFrom' => $login]));
        $this->assertSame(200, $response->getStatusCode());
        $this->assertNotNull(AccessToken::whereToken($token)->first());
        $this->assertSame(0, $this->logoutEvents);
    }

    public function test_automatic_logout_return_is_validated_by_flarum(): void
    {
        $login = $this->login();
        $response = $this->send($this->request('POST', '/logout', ['cookiesFrom' => $login])
            ->withQueryParams(['redirect' => 'false', 'return' => 'https://evil.example/'])
            ->withParsedBody(['csrfToken' => $login->getHeaderLine('X-CSRF-Token')]));
        $this->assertSame('http://localhost', $response->getHeaderLine('Location'));
    }
}
