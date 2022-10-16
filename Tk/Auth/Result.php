<?php
namespace Tk\Auth;

/**
 * Auth result object
 *
 * @author Tropotek <http://www.tropotek.com/>
 */
class Result
{
    
    /**
     * General Failure
     */
    const FAILURE                       =  0;

    /**
     * Failure due to identity not being found.
     */
    const FAILURE_IDENTITY_NOT_FOUND    = -1;

    /**
     * Failure due to identity being ambiguous.
     */
    const FAILURE_IDENTITY_AMBIGUOUS    = -2;

    /**
     * Failure due to invalid credential being supplied.
     */
    const FAILURE_CREDENTIAL_INVALID    = -3;

    /**
     * Failure due to unknown reasons.
     */
    const FAILURE_UNKNOWN               = -4;

    /**
     * Authentication success.
     */
    const SUCCESS                       =  1;


    /**
     * Authentication result code
     */
    protected int $code = 0;

    /**
     * The identity used in the authentication attempt
     *
     * @var mixed
     */
    protected $identity = null;

    protected string $message = '';


    /**
     * Sets the result code, identity, and failure messages
     *
     * @param  mixed   $identity
     */
    public function __construct(int $code, $identity, string $message = '')
    {
        $this->code     = $code;
        $this->identity = $identity;
        $this->message = $message;
    }

    /**
     * Returns whether the result represents a successful authentication attempt
     */
    public function isValid(): bool
    {
        return ($this->code > 0);
    }

    /**
     * getCode() - Get the result code for this authentication attempt
     */
    public function getCode(): int
    {
        return $this->code;
    }

    /**
     * Returns the identity used in the authentication attempt
     */
    public function getIdentity(): ?string
    {
        return $this->identity;
    }

    /**
     * Should return why the authentication attempt was unsuccessful
     */
    public function getMessage(): string
    {
        return $this->message;
    }
}
