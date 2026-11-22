<?php
declare(strict_types=1);

namespace KSeven\WebLicense;

use KSeven\WebLicense\Crypto\Codec;
use KSeven\WebLicense\Storage\EncryptedStateStore;
use RuntimeException;

/**
 * K'Seven Web Licensing SDK (PHP 8.1+ Composer PSR-4)
 * - Estado local criptografado (AES-256-GCM + HKDF-SHA256)
 * - Transporte cifrado opcional/padrão (ECDH P-256 + AES-256-GCM k7seal.v1)
 * - Operações completas: install, checkVersion, update, validate, entitlements, leases, uninstall
 */
final class WebLicenseClient
{
    private string $apiBaseUrl;
    private string $platform;
    private int $timeoutSeconds;
    private bool $allowInsecureLocalHttp;
    private bool $useEncryptedTransport;
    /** @var array<string, string> */
    private array $pinnedPublicKeys;
    private EncryptedStateStore $stateStore;
    /** @var array{sessionId: string, aesKey: string, expiresAt: int}|null */
    private ?array $wireSession = null;

    /**
     * @param array{
     *   apiBaseUrl: string,
     *   stateFilePath?: string,
     *   stateSecret?: string,
     *   platform?: string,
     *   timeoutSeconds?: int,
     *   allowInsecureLocalHttp?: bool,
     *   useEncryptedTransport?: bool,
     *   pinnedPublicKeys?: array<string, string>
     * } $config
     */
    public function __construct(array $config)
    {
        if (empty($config['apiBaseUrl'])) {
            throw new RuntimeException('apiBaseUrl é obrigatório.');
        }

        $this->apiBaseUrl = rtrim((string) $config['apiBaseUrl'], '/');
        $this->allowInsecureLocalHttp = (bool) ($config['allowInsecureLocalHttp'] ?? false);
        $this->assertAllowedUrl($this->apiBaseUrl);

        $stateFilePath = (string) ($config['stateFilePath'] ?? (getcwd() . '/.kseven-web-license.dat'));
        $stateSecret = isset($config['stateSecret']) ? (string) $config['stateSecret'] : null;
        $this->stateStore = new EncryptedStateStore($stateFilePath, $stateSecret);

        $this->platform = (string) ($config['platform'] ?? 'php');
        $this->timeoutSeconds = max(3, (int) ($config['timeoutSeconds'] ?? 15));
        $this->useEncryptedTransport = ($config['useEncryptedTransport'] ?? true) !== false;
        $this->pinnedPublicKeys = $config['pinnedPublicKeys'] ?? [];
    }

    public function createDomainChallenge(string $licenseKey, string $domain, string $method = 'DNS_TXT'): array
    {
        return $this->request('POST', '/domain-challenges', [
            'licenseKey' => $licenseKey,
            'domain' => $domain,
            'method' => $method,
        ]);
    }

    public function verifyDomainChallenge(string $challengeId, ?string $licenseKey = null): array
    {
        $body = $licenseKey ? ['licenseKey' => $licenseKey] : [];
        return $this->request('POST', '/domain-challenges/' . rawurlencode($challengeId) . '/verify', $body);
    }

    /**
     * INSTALL: ativa a instalação e persiste credencial cifrada em AES-256-GCM (0600).
     *
     * @param array{
     *   licenseKey: string,
     *   domain: string,
     *   appVersion: string,
     *   platform?: string,
     *   environment?: string,
     *   instanceFingerprint?: string,
     *   idempotencyKey?: string
     * } $options
     */
    public function install(array $options): array
    {
        $platform = $options['platform'] ?? $this->platform;
        $environment = $options['environment'] ?? 'production';
        $fingerprint = $options['instanceFingerprint'] ?? substr(
            hash('sha256', gethostname() . ':' . $platform . ':' . $options['domain']),
            0,
            32
        );
        $idempotencyKey = $options['idempotencyKey'] ?? "install-{$platform}-{$fingerprint}";

        $res = $this->request('POST', '/activate', [
            'licenseKey' => $options['licenseKey'],
            'domain' => $options['domain'],
            'platform' => $platform,
            'appVersion' => $options['appVersion'],
            'environment' => $environment,
            'instanceFingerprint' => $fingerprint,
            'idempotencyKey' => $idempotencyKey,
        ]);

        $publicKeys = $this->fetchPublicKeysMap();
        $now = gmdate('c');

        $state = [
            'apiBaseUrl' => $this->apiBaseUrl,
            'installationId' => $res['installationId'],
            'installationCredential' => $res['installationCredential'],
            'credentialPrefix' => $res['credentialPrefix'] ?? null,
            'credentialVersion' => $res['credentialVersion'] ?? 1,
            'domain' => $res['domain'],
            'platform' => $res['platform'],
            'appVersion' => $res['appVersion'],
            'environment' => $environment,
            'instanceFingerprint' => $fingerprint,
            'installedAt' => $now,
            'updatedAt' => $now,
            'pinnedPublicKeys' => $publicKeys,
        ];

        $this->stateStore->write($state);

        return [
            'installed' => true,
            'installationId' => $state['installationId'],
            'domain' => $state['domain'],
            'platform' => $state['platform'],
            'appVersion' => $state['appVersion'],
            'idempotentReplay' => (bool) ($res['idempotentReplay'] ?? false),
            'encryptedTransport' => $this->wireSession !== null,
            'entitlement' => $res['entitlement'] ?? null,
        ];
    }

    public function validate(?string $appVersion = null): array
    {
        $state = $this->requireState();
        $payload = ['domain' => $state['domain']];
        if ($appVersion !== null && $appVersion !== '') {
            $payload['appVersion'] = $appVersion;
        }
        $res = $this->request('POST', '/validate', $payload, $state['installationCredential']);
        if ($appVersion !== null && $appVersion !== '' && $appVersion !== $state['appVersion']) {
            $state['appVersion'] = $appVersion;
            $state['updatedAt'] = gmdate('c');
            $this->stateStore->write($state);
        }
        return $res;
    }

    public function entitlements(): array
    {
        $state = $this->requireState();
        return $this->request('GET', '/entitlements', null, $state['installationCredential']);
    }

    public function acquireLease(int $ttlSeconds = 180, ?string $idempotencyKey = null): array
    {
        $state = $this->requireState();
        $payload = ['ttlSeconds' => $ttlSeconds];
        if ($idempotencyKey !== null && $idempotencyKey !== '') {
            $payload['idempotencyKey'] = $idempotencyKey;
        }
        return $this->request('POST', '/leases/acquire', $payload, $state['installationCredential']);
    }

    public function heartbeatLease(string $leaseId, ?string $leaseToken = null): array
    {
        $state = $this->requireState();
        $payload = $leaseToken ? ['leaseToken' => $leaseToken] : [];
        return $this->request('POST', '/leases/' . rawurlencode($leaseId) . '/heartbeat', $payload, $state['installationCredential']);
    }

    public function releaseLease(string $leaseId): array
    {
        $state = $this->requireState();
        return $this->request('POST', '/leases/' . rawurlencode($leaseId) . '/release', [], $state['installationCredential']);
    }

    public function checkVersion(string $channel = 'stable', ?string $currentVersion = null): array
    {
        $state = $this->requireState();
        $ch = $channel === 'beta' ? 'beta' : 'stable';
        $ver = $currentVersion ?: $state['appVersion'];

        $query = http_build_query(['channel' => $ch, 'currentVersion' => $ver]);
        $res = $this->request('GET', '/updates/check?' . $query, null, $state['installationCredential']);

        if (empty($res['latestRelease'])) {
            return [
                'updateAvailable' => false,
                'channel' => $ch,
                'currentVersion' => $ver,
                'latestRelease' => null,
                'signatureVerified' => true,
            ];
        }

        $rel = $res['latestRelease'];
        $keysMap = $this->fetchPublicKeysMap($state['pinnedPublicKeys'] ?? []);
        $keyId = (string) ($rel['signingKeyId'] ?? '');
        $pem = $this->pinnedPublicKeys[$keyId] ?? $keysMap[$keyId] ?? ($rel['publicKeyPem'] ?? '');
        if (!$pem) {
            throw new RuntimeException("Chave pública Ed25519 ausente para keyId={$keyId}");
        }

        $manifest = Codec::verifyEd25519Manifest(
            (string) $rel['manifestJson'],
            (string) $rel['manifestSignature'],
            $pem
        );

        if (
            ($manifest['version'] ?? '') !== ($rel['version'] ?? '') ||
            ($manifest['packageSha256'] ?? '') !== ($rel['packageSha256'] ?? '')
        ) {
            throw new RuntimeException('Divergência entre manifesto assinado e metadados da release.');
        }

        return [
            'updateAvailable' => !empty($res['updateAvailable']),
            'channel' => $ch,
            'currentVersion' => $res['currentVersion'] ?? $ver,
            'latestRelease' => $rel,
            'signatureVerified' => true,
        ];
    }

    public function update(array $options = []): array
    {
        $state = $this->requireState();
        $channel = $options['channel'] ?? 'stable';
        $check = $this->checkVersion($channel, $options['currentVersion'] ?? null);

        if (empty($check['updateAvailable']) || empty($check['latestRelease'])) {
            return [
                'updated' => false,
                'previousVersion' => $state['appVersion'],
                'currentVersion' => $state['appVersion'],
                'release' => $check['latestRelease'] ?? null,
                'signatureVerified' => true,
            ];
        }

        $rel = $check['latestRelease'];
        $grant = $this->request(
            'POST',
            '/updates/' . (int) $rel['releaseId'] . '/download-grants',
            ['maxDownloads' => 1],
            $state['installationCredential']
        );

        $consumed = $this->request(
            'GET',
            '/updates/download/' . rawurlencode((string) $grant['grantId']),
            null,
            null,
            ['x-download-grant-token: ' . $grant['grantToken']]
        );

        $keysMap = $this->fetchPublicKeysMap($state['pinnedPublicKeys'] ?? []);
        $keyId = (string) ($consumed['signingKeyId'] ?? '');
        $pem = $this->pinnedPublicKeys[$keyId] ?? $keysMap[$keyId] ?? ($rel['publicKeyPem'] ?? '');
        if (!$pem) {
            throw new RuntimeException("Chave pública Ed25519 ausente para keyId={$keyId}");
        }

        $verifiedManifest = Codec::verifyEd25519Manifest(
            (string) $consumed['manifestJson'],
            (string) $consumed['manifestSignature'],
            $pem
        );

        $packageUrl = (string) ($consumed['packageUrl'] ?? '');
        if (str_starts_with($packageUrl, '/api/')) {
            $packageUrl = $this->apiBaseUrl . $packageUrl;
        }
        $this->assertAllowedUrl($packageUrl);

        $tmpFile = tempnam(sys_get_temp_dir(), 'k7pkg_');
        if ($tmpFile === false) {
            throw new RuntimeException('Falha ao criar arquivo temporário de download.');
        }

        try {
            $this->downloadFile($packageUrl, $tmpFile);
            $actualSha = strtolower((string) hash_file('sha256', $tmpFile));
            $expectedSha = strtolower((string) $verifiedManifest['packageSha256']);
            if (!hash_equals($expectedSha, $actualSha)) {
                throw new RuntimeException("SHA-256 inválido: esperado {$expectedSha}, obtido {$actualSha}.");
            }
            $expectedSize = (int) ($verifiedManifest['packageSizeBytes'] ?? 0);
            if ($expectedSize > 0 && filesize($tmpFile) !== $expectedSize) {
                throw new RuntimeException('Tamanho do pacote diverge do manifesto assinado.');
            }

            $savedFilePath = null;
            if (!empty($options['destDir'])) {
                $fileName = $options['downloadFileName'] ?? ($rel['productSlug'] . '-' . $rel['version'] . '-' . $rel['platform'] . '.pkg');
                $savedFilePath = $this->resolveSafeChildPath((string) $options['destDir'], (string) $fileName);
                if (!is_dir((string) $options['destDir'])) {
                    mkdir((string) $options['destDir'], 0750, true);
                }
                if (!copy($tmpFile, $savedFilePath)) {
                    throw new RuntimeException('Não foi possível gravar o pacote verificado no destino.');
                }
                @chmod($savedFilePath, 0640);
            }

            if (isset($options['onVerifiedPackage']) && is_callable($options['onVerifiedPackage'])) {
                ($options['onVerifiedPackage'])($tmpFile, $rel);
            }
        } finally {
            if (is_file($tmpFile)) {
                @unlink($tmpFile);
            }
        }

        $prev = $state['appVersion'];
        $this->validate((string) $rel['version']);

        return [
            'updated' => true,
            'previousVersion' => $prev,
            'currentVersion' => (string) $rel['version'],
            'release' => $rel,
            'savedFilePath' => $savedFilePath,
            'verifiedSha256' => $actualSha,
            'signatureVerified' => true,
        ];
    }

    public function uninstall(string $reason = 'PHP_SDK_UNINSTALL'): array
    {
        $state = $this->readState();
        if (!$state || empty($state['installationCredential'])) {
            return [
                'uninstalled' => true,
                'alreadyUninstalled' => true,
                'installationId' => null,
            ];
        }

        try {
            $this->request('POST', '/deactivate', ['reason' => $reason], $state['installationCredential']);
        } catch (RuntimeException $e) {
            if ((int) $e->getCode() !== 401 && (int) $e->getCode() !== 403) {
                throw $e;
            }
        }

        $this->stateStore->write(null);

        return [
            'uninstalled' => true,
            'alreadyUninstalled' => false,
            'installationId' => $state['installationId'],
        ];
    }

    public function readState(): ?array
    {
        return $this->stateStore->read();
    }

    private function requireState(): array
    {
        $state = $this->readState();
        if (!$state || empty($state['installationCredential'])) {
            throw new RuntimeException('Instalação não encontrada localmente. Execute install() primeiro.');
        }
        return $state;
    }

    private function ensureWireSession(): ?array
    {
        if (!$this->useEncryptedTransport || !function_exists('openssl_pkey_derive')) {
            return null;
        }
        if ($this->wireSession !== null && time() < $this->wireSession['expiresAt']) {
            return $this->wireSession;
        }

        try {
            $eph = Codec::createEphemeralEcdhKeyPair();
            $url = $this->apiBaseUrl . '/api/web/license/v1/session-key';
            $ch = curl_init($url);
            curl_setopt_array($ch, [
                CURLOPT_CUSTOMREQUEST => 'POST',
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_HTTPHEADER => ['Accept: application/json', 'Content-Type: application/json'],
                CURLOPT_POSTFIELDS => json_encode(['clientPublicKeySpkiBase64' => $eph['clientPublicKeySpkiBase64']]),
                CURLOPT_TIMEOUT => $this->timeoutSeconds,
                CURLOPT_FOLLOWLOCATION => false,
            ]);
            $raw = curl_exec($ch);
            $status = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);

            if ($raw === false || $status < 200 || $status >= 300) {
                return null;
            }
            $data = json_decode((string) $raw, true);
            if (!is_array($data) || empty($data['sessionId']) || empty($data['serverPublicKeySpkiBase64'])) {
                return null;
            }
            $aesKey = Codec::deriveWireAesKey(
                $eph['privateKey'],
                (string) $data['sessionId'],
                (string) $data['serverPublicKeySpkiBase64']
            );
            $ttl = max(60, (int) ($data['expiresInSeconds'] ?? 1800) - 30);
            $this->wireSession = [
                'sessionId' => (string) $data['sessionId'],
                'aesKey' => $aesKey,
                'expiresAt' => time() + $ttl,
            ];
            return $this->wireSession;
        } catch (\Throwable) {
            return null;
        }
    }

    private function resolveSafeChildPath(string $baseDir, string $fileName): string
    {
        $cleanName = basename($fileName);
        if ($cleanName === '' || $cleanName === '.' || $cleanName === '..' || $cleanName !== ltrim($fileName, '/\\')) {
            throw new RuntimeException('Nome de arquivo inválido (path traversal bloqueado).');
        }
        $realBase = realpath($baseDir) ?: $baseDir;
        return rtrim($realBase, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $cleanName;
    }

    private function assertAllowedUrl(string $url): void
    {
        $parts = parse_url($url);
        if (!$parts || empty($parts['scheme']) || empty($parts['host'])) {
            throw new RuntimeException('URL inválida.');
        }
        $scheme = strtolower((string) $parts['scheme']);
        $host = strtolower((string) $parts['host']);
        if ($scheme === 'https') {
            return;
        }
        if ($scheme === 'http' && $this->allowInsecureLocalHttp && in_array($host, ['127.0.0.1', 'localhost', '::1'], true)) {
            return;
        }
        throw new RuntimeException("Somente URLs HTTPS são permitidas em produção ({$scheme}://{$host}).");
    }

    /**
     * @return array<string, string>
     */
    private function fetchPublicKeysMap(array $fallback = []): array
    {
        try {
            $res = $this->request('GET', '/releases/public-key');
            $out = array_merge($fallback, $this->pinnedPublicKeys);
            foreach (($res['keys'] ?? []) as $item) {
                if (!empty($item['keyId']) && !empty($item['publicKeyPem'])) {
                    $out[(string) $item['keyId']] = (string) $item['publicKeyPem'];
                }
            }
            return $out;
        } catch (\Throwable) {
            return array_merge($fallback, $this->pinnedPublicKeys);
        }
    }

    private function request(
        string $method,
        string $endpointPath,
        ?array $body = null,
        ?string $credential = null,
        array $extraHeaders = [],
        bool $retryOnSessionExpired = true
    ): array {
        $url = $this->apiBaseUrl . '/api/web/license/v1' . $endpointPath;
        $this->assertAllowedUrl($url);

        $pathOnly = '/api/web/license/v1' . explode('?', $endpointPath, 2)[0];
        $aad = strtoupper($method) . ':' . $pathOnly;
        $session = $this->ensureWireSession();

        $headers = array_merge(['Accept: application/json'], $extraHeaders);
        if ($credential !== null && $credential !== '') {
            $headers[] = 'x-web-installation-credential: ' . $credential;
        }

        $postBody = null;
        if ($session !== null) {
            $headers[] = 'x-k7-web-session: ' . $session['sessionId'];
            $headers[] = 'x-k7-web-cipher: aes-256-gcm';
            if ($body !== null) {
                $headers[] = 'Content-Type: application/json';
                $postBody = json_encode([
                    'sealed' => true,
                    'sealedEnvelope' => Codec::sealWirePayload($body, $session['aesKey'], $aad),
                ]);
            }
        } elseif ($body !== null) {
            $headers[] = 'Content-Type: application/json';
            $postBody = json_encode($body);
        }

        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_CUSTOMREQUEST => $method,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => $headers,
            CURLOPT_TIMEOUT => $this->timeoutSeconds,
            CURLOPT_FOLLOWLOCATION => false,
        ]);
        if ($postBody !== null) {
            curl_setopt($ch, CURLOPT_POSTFIELDS, $postBody);
        }

        $raw = curl_exec($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curlErr = curl_error($ch);
        curl_close($ch);

        if ($raw === false) {
            throw new RuntimeException('Erro de comunicação HTTP: ' . $curlErr, 503);
        }

        if ($status === 428 && $session !== null && $retryOnSessionExpired) {
            $this->wireSession = null;
            return $this->request($method, $endpointPath, $body, $credential, $extraHeaders, false);
        }

        $decoded = json_decode((string) $raw, true);
        if (
            $session !== null &&
            is_array($decoded) &&
            !empty($decoded['sealed']) &&
            !empty($decoded['sealedEnvelope'])
        ) {
            $decoded = Codec::unsealWirePayload((string) $decoded['sealedEnvelope'], $session['aesKey'], $aad);
        }

        if ($status < 200 || $status >= 300) {
            $msg = is_array($decoded) && !empty($decoded['message']) ? (string) $decoded['message'] : "Erro HTTP {$status}";
            throw new RuntimeException($msg, $status);
        }

        return is_array($decoded) ? $decoded : [];
    }

    private function downloadFile(string $url, string $destPath): void
    {
        $fp = fopen($destPath, 'wb');
        if ($fp === false) {
            throw new RuntimeException('Não foi possível abrir arquivo temporário para escrita.');
        }
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_FILE => $fp,
            CURLOPT_TIMEOUT => max($this->timeoutSeconds, 60),
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS => 3,
        ]);
        $ok = curl_exec($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $err = curl_error($ch);
        curl_close($ch);
        fclose($fp);

        if (!$ok || $status < 200 || $status >= 300) {
            throw new RuntimeException("Falha no download do pacote (HTTP {$status}): {$err}");
        }
    }
}
