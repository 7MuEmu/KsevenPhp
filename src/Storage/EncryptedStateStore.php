<?php
declare(strict_types=1);

namespace KSeven\WebLicense\Storage;

use KSeven\WebLicense\Crypto\Codec;

final class EncryptedStateStore
{
    private string $filePath;
    private ?string $secret;

    public function __construct(string $filePath, ?string $secret = null)
    {
        $this->filePath = $filePath;
        $this->secret = $secret;
    }

    public function read(): ?array
    {
        if (!is_file($this->filePath)) {
            return null;
        }
        $raw = file_get_contents($this->filePath);
        if ($raw === false || trim($raw) === '') {
            return null;
        }
        return Codec::decodeEncryptedState($raw, $this->secret);
    }

    public function write(?array $state): void
    {
        if ($state === null) {
            if (is_file($this->filePath)) {
                @unlink($this->filePath);
            }
            return;
        }

        $dir = dirname($this->filePath);
        if (!is_dir($dir)) {
            mkdir($dir, 0750, true);
        }
        $sealed = Codec::encodeEncryptedState($state, $this->secret);
        $tmp = $this->filePath . '.tmp.' . bin2hex(random_bytes(4));
        file_put_contents($tmp, $sealed);
        @chmod($tmp, 0600);
        rename($tmp, $this->filePath);
    }
}
