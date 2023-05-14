<?php
namespace Tk\Auth\Adapter;

use Bs\Db\UserInterface;
use Tk\Auth\Auth;
use Tk\Auth\Result;
use Tk\Db\Mapper\Mapper;

/**
 * A DB table authenticator adaptor
 *
 * This adaptor requires that the password and username are submitted in a POST request
 * @see https://www.php.net/manual/en/function.password-hash.php
 */
class AuthUser extends AdapterInterface
{

    protected Mapper $mapper;


    public function __construct(Mapper $mapper)
    {
        $this->mapper = $mapper;
    }

    public function authenticate(): Result
    {
        // get values from a post request only
        $username = $this->getFactory()->getRequest()->request->get('username');
        $password = $this->getFactory()->getRequest()->request->get('password');

        if (!$username || !$password) {
            return new Result(Result::FAILURE_CREDENTIAL_INVALID, $username, 'No username or password.');
        }

        try {
            $user = $this->mapper->findByUsername($username);
            if ($user && password_verify($password, $user->getPassword())) {
                return new Result(Result::SUCCESS, $username);
            }
        } catch (\Exception $e) {
            \Tk\Log::warning($e->__toString());
        }
        return new Result(Result::FAILURE_IDENTITY_NOT_FOUND, $username, 'Invalid username or password.');
    }

}
