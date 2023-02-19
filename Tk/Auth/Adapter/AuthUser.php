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
 *
 * @author Tropotek <http://www.tropotek.com/>
 */
class AuthUser extends AdapterInterface
{

    protected Mapper $mapper;


    public function __construct(Mapper $mapper)
    {
        $this->mapper = $mapper;
    }

    /**
     * This will hash the password using the $user->hash value as a salt if it exists.
     * You can override the hash function by using DbTable::setOnHash(callable)
     */
    public function hashPassword(string $password, UserInterface $user): string
    {
        return Auth::hashPassword($password, $user->getHash() ?? null);
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
            if ($user && $this->hashPassword($password, $user) == $user->getPassword()) {
                return new Result(Result::SUCCESS, $username);
            }
        } catch (\Exception $e) {
            \Tk\Log::warning($e->__toString());
        }
        return new Result(Result::FAILURE_IDENTITY_NOT_FOUND, $username, 'Invalid username or password.');
    }

}
