<?php
namespace Bs\Listener;

use Bs\Db\User;
use Tk\ConfigTrait;
use Tk\Event\Subscriber;
use Symfony\Component\HttpKernel\KernelEvents;
use Tk\Event\AuthEvent;
use Tk\Auth\AuthEvents;
use Tk\ExtAuth\Microsoft\Token;
use Tk\ExtAuth\Microsoft\TokenMap;

/**
 * @todo Implement this after we get the code operational
 */
class AuthHandler implements Subscriber
{
    use ConfigTrait;

    /**
     * @param \Symfony\Component\HttpKernel\Event\GetResponseEvent $event
     * @throws \Exception
     */
    public function onRequest($event)
    {

    }


    /**
     * @param AuthEvent $event
     * @throws \Exception
     */
    public function onLogin(AuthEvent $event)
    {


    }

    /**
     * @param AuthEvent $event
     * @throws \Exception
     */
    public function onLoginSuccess(AuthEvent $event)
    {

    }

    /**
     * @param AuthEvent $event
     * @throws \Exception
     */
    public function onLogout(AuthEvent $event)
    {
        if ($this->getConfig()->get('auth.microsoft.enabled', false)) {
            $token = TokenMap::create()->findBySessionKey($this->getSession()->get(Token::SESSION_KEY));
            if ($token) {
                $token->delete();
                $event->setRedirect(\Tk\Uri::create($this->getConfig()->get('auth.microsoft.logout')));
            }
        }
    }


    public static function getSubscribedEvents()
    {
        return [
            KernelEvents::REQUEST => ['onRequest', 5],
            AuthEvents::LOGIN => 'onLogin',
            AuthEvents::LOGIN_SUCCESS => ['onLoginSuccess', 5],
            AuthEvents::LOGOUT => 'onLogout'
        ];
    }
}
