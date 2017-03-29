<?php
namespace Tk\Auth;

/**
 * @author Michael Mifsud <info@tropotek.com>
 * @link http://www.tropotek.com/
 * @license Copyright 2016 Michael Mifsud
 */
final class AuthEvents
{

    /**
     * Called when a user wants to login.
     * All Authentication should take place here.
     *
     * @event \App\Event\AuthEvent
     */
    const LOGIN = 'auth.onLogin';

    /**
     * Called when a user successfully logs in
     *
     * @event \App\Event\AuthEvent
     */
    const LOGIN_SUCCESS = 'auth.onLoginSuccess';

    /**
     * Called when a user logs out of the system
     *
     * @event \App\Event\AuthEvent
     */
    const LOGOUT = 'auth.onLogout';

    /**
     * Called when a user wants to recover their account password
     * This should email a message with a URL to set the new password for the account
     *
     * @event \Tk\Event\Event
     */
    const RECOVER = 'auth.onRecover';

    /**
     * This is called when the user has set the new password for the account
     *
     * @event \Tk\Event\Event
     */
    const RECOVER_PASS = 'auth.onRecoverPass';

    /**
     * Called when a new user submits a registration request
     *
     * @event \Tk\Event\Event
     */
    const REGISTER = 'auth.onRegister';

    /**
     * Called when a user triggers the registration confirmation request
     *
     * @event \Tk\Event\Event
     */
    const REGISTER_CONFIRM = 'auth.onRegisterConfirm';

}