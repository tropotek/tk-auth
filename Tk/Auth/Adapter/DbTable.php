<?php
namespace Tk\Auth\Adapter;

use Tk\Auth\Auth;
use Tk\Auth\Result;
use Tk\Db\Pdo;

/**
 * A DB table authenticator adaptor
 *
 * This adaptor requires that the password and username are submitted in a POST request
 */
class DbTable extends AdapterInterface
{

    protected string $tableName = 'user';

    protected string $usernameColumn = 'username';

    protected string $passwordColumn = 'password';

    protected Pdo $db;


    public function __construct(Pdo $db, string $tableName = 'user', string $userColumn = 'username', string $passColumn = 'password')
    {
        $this->db = $db;
        $this->tableName = $tableName;
        $this->usernameColumn = $userColumn;
        $this->passwordColumn = $passColumn;
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
            if ($user && password_verify($password, $user->{$this->passwordColumn})) {
                return new Result(Result::SUCCESS, $username);
            }
        } catch (\Exception $e) {
            \Tk\Log::warning($e->__toString());
        }
        return new Result(Result::FAILURE_IDENTITY_NOT_FOUND, $username, 'Invalid username or password.');
    }

}
