<?php
declare(strict_types=1);

namespace KSeven\WebLicense\Storage;

use KSeven\WebLicense\Crypto\Codec;

/**
 * Gerenciador de persistência em disco para o estado da licença criptografado (AES-256-GCM + HKDF-SHA256).
 * Realiza leitura autenticada e gravação atômica com permissões restritas (`0600`).
 */
final class EncryptedStateStore
{
    /** @var string Caminho completo do arquivo onde o estado cifrado é armazenado em disco. */
    private string $filePath;

    /** @var string|null Segredo mestre opcional usado na derivação da chave simétrica; se nulo, o Codec resolve automaticamente. */
    private ?string $secret;

    /**
     * Inicializa o armazenamento criptografado apontando para o arquivo de estado e seu segredo de cifragem.
     *
     * @param string $filePath Caminho do arquivo de estado local (ex.: `/storage/.kseven-web-license.dat`).
     * @param string|null $secret Segredo personalizado opcional para cifrar/decifrar o conteúdo.
     */
    public function __construct(string $filePath, ?string $secret = null)
    {
        $this->filePath = $filePath;
        $this->secret = $secret;
    }

    /**
     * Lê o arquivo de estado do disco, decifra e valida sua autenticidade via `Codec::decodeEncryptedState()`.
     *
     * @return array<string, mixed>|null Dados do estado decifrado ou `null` caso o arquivo não exista ou esteja vazio.
     * @throws \RuntimeException Se o envelope estiver corrompido ou a chave/segredo não corresponder.
     */
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

    /**
     * Cifra e grava o estado da instalação de forma atômica (arquivo temporário com permissão `0600` seguido de `rename()`),
     * ou remove o arquivo de estado do disco caso `$state` seja `null`.
     *
     * @param array<string, mixed>|null $state Dados do estado a serem persistidos, ou `null` para excluir o arquivo.
     * @return void
     * @throws \RuntimeException Se a cifragem AES-256-GCM falhar.
     * @throws \JsonException Se o array `$state` não puder ser serializado em JSON.
     */
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