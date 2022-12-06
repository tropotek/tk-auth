<?php
namespace Tk\ExtAuth\Microsoft;

use Tk\Date;
use Tk\Db\Map\Model;
use Tk\Uri;

class Token extends Model
{
    const SESSION_KEY = 'auth.ms.sessionKey';

    /**
     * @var int
     */
    public $id = 0;

    /**
     * @var int
     */
    public $userId = 0;

    public $sessionKey = '';

    /**
     * @var null|\DateTime
     */
    public $expires = null;

    public $redirect = '';

    public $refreshToken = '';

    public $codeVerifier = '';

    public $token = '';

    /**
     * Json object???
     * @var string|array
     */
    public $idToken = '';


    public function __construct()
    {
        $this->expires = Date::create()->add(new \DateInterval('PT5M'));
    }

    public static function create(string $sessionKey, string $redirect, string $codeVerifier): Token
    {
        $obj = new static();
        $obj->sessionKey = $sessionKey;
        $obj->redirect = $redirect;
        $obj->codeVerifier = $codeVerifier;
        return $obj;
    }

    public function isExpiring(): bool
    {
        return ($this->expires < Date::create($this->expires)->add(new \DateInterval('PT10M')));
    }




    /**
     * Generate A UUID for a session key
     * @return string
     */
    public static function makeSessionKey(): string
    {
        //uuid function is not my code, but unsure who the original author is. KN
        //uuid version 4
        return sprintf('%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
            // 32 bits for "time_low"
            mt_rand(0, 0xffff), mt_rand(0, 0xffff),
            // 16 bits for "time_mid"
            mt_rand(0, 0xffff),
            // 16 bits for "time_hi_and_version",
            // four most significant bits holds version number 4
            mt_rand(0, 0x0fff) | 0x4000,
            // 16 bits, 8 bits for "clk_seq_hi_res",
            // 8 bits for "clk_seq_low",
            // two most significant bits holds zero and one for variant DCE1.1
            mt_rand(0, 0x3fff) | 0x8000,
            // 48 bits for "node"
            mt_rand(0, 0xffff), mt_rand(0, 0xffff), mt_rand(0, 0xffff)
        );
    }
}