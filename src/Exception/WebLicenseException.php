<?php
declare(strict_types=1);

namespace KSeven\WebLicense\Exception;

use RuntimeException;
use Throwable;

/**
 * Exceção estruturada do SDK PHP de Licenciamento Web K'Seven.
 * Preserva o código HTTP, o código de erro da API (`errorCode`) e os detalhes
 * diagnósticos retornados pelo servidor sem ocultar a causa da rejeição.
 */
final class WebLicenseException extends RuntimeException
{
    /**
     * @param string $message Mensagem legível retornada pela API ou pelo SDK.
     * @param int $httpStatus Código HTTP associado (0 ou 503 em erro de rede).
     * @param string $errorCode Código simbólico retornado pela API (ex.: LOCALHOST_DEVELOPMENT_NOT_ALLOWED).
     * @param array<string, mixed> $details Payload sanitizado adicional retornado pela API, quando disponível.
     * @param Throwable|null $previous Exceção anterior, se houver.
     */
    public function __construct(
        string $message,
        public readonly int $httpStatus = 0,
        public readonly string $errorCode = 'SDK_ERROR',
        public readonly array $details = [],
        ?Throwable $previous = null
    ) {
        $formatted = $errorCode !== '' && !str_contains($message, $errorCode)
            ? "[{$errorCode}] {$message}"
            : $message;
        parent::__construct($formatted, $httpStatus, $previous);
    }

    public function getHttpStatus(): int
    {
        return $this->httpStatus;
    }

    public function getErrorCode(): string
    {
        return $this->errorCode;
    }

    public function getRequestId(): ?string
    {
        $reqId = $this->details['requestId'] ?? null;
        return is_string($reqId) && $reqId !== '' ? $reqId : null;
    }

    /**
     * @return array<string, mixed>
     */
    public function getDetails(): array
    {
        return $this->details;
    }
}
