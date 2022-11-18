<?php
namespace Tk\Auth;

use Tk\Auth\Adapter\AdapterInterface;

/**
 * @author Tropotek <http://www.tropotek.com/>
 */
interface FactoryInterface
{

    /**
     * Create and return a valid Auth controller for user authentication
     */
    public function getAuthController(): Auth;

    /**
     * This is the default Authentication adapter
     * Override this method in your own site's Factory object
     */
    public function getAuthAdapter(): AdapterInterface;

    /**
     * Return a User object or record that is located from the Auth's getIdentity() method
     * Override this method in your own site's Factory object
     */
    public function getAuthUser(): mixed;

}