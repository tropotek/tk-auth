<?php
namespace Tk\Auth\Adapter;

use Tk\Auth\Auth;
use Tk\Auth\Result;
use Tk\Db\Pdo;

/**
 * A DB table authenticator adaptor
 *
 * This adaptor requires that the password and username are submitted in a POST request
 *
 * @author Tropotek <http://www.tropotek.com/>
 */
class DbTable extends AdapterInterface
{

    protected string $tableName = '';

    protected string $usernameColumn = '';

    protected string $passwordColumn = '';

    protected Pdo $db;


    public function __construct(Pdo $db, string $tableName, string $userColumn, string $passColumn)
    {
        $this->db = $db;
        $this->tableName = $tableName;
        $this->usernameColumn = $userColumn;
        $this->passwordColumn = $passColumn;
    }

    /**
     * This will hash the password using the $user->hash value as a salt if it exists.
     * You can override the hash function by using DbTable::setOnHash(callable)
     */
    public function hashPassword(string $password, $user = null): string
    {
        if ($this->getOnHash()) {
            return call_user_func_array($this->getOnHash(), [$password, $user]);
        }
        return Auth::hashPassword($password, $user->hash ?? null);
    }

    protected function getUserRow(string $username): object|false
    {
        $sql = sprintf('SELECT * FROM %s WHERE %s = :username LIMIT 1',
            $this->db->quoteParameter($this->tableName),
            $this->db->quoteParameter($this->usernameColumn)
        );

        $stmt = $this->db->prepare($sql);
        $stmt->execute(compact($username));

        return $stmt->fetchObject();
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
            $user = $this->getUserRow($username);
            if ($user && $this->hashPassword($password, $user) == $user->{$this->passwordColumn}) {
                return new Result(Result::SUCCESS, $username);
            }
        } catch (\Exception $e) {
            \Tk\Log::warning($e->__toString());
        }
        return new Result(Result::FAILURE_IDENTITY_NOT_FOUND, $username, 'Invalid username or password.');
    }

}
