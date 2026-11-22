#!/usr/bin/env php
<?php
declare(strict_types=1);

$autoloadCandidates = [
    dirname(__DIR__) . '/vendor/autoload.php',
    dirname(__DIR__, 3) . '/autoload.php',
];
$loaded = false;
foreach ($autoloadCandidates as $autoload) {
    if (is_file($autoload)) {
        require_once $autoload;
        $loaded = true;
        break;
    }
}
if (!$loaded) {
    require_once dirname(__DIR__) . '/src/Crypto/Codec.php';
    require_once dirname(__DIR__) . '/src/Storage/EncryptedStateStore.php';
    require_once dirname(__DIR__) . '/src/WebLicenseClient.php';
}

use KSeven\WebLicense\WebLicenseClient;

$args = array_slice($argv, 1);
$command = $args[0] ?? 'help';
$flags = [];
for ($i = 1; $i < count($args); $i++) {
    $token = $args[$i];
    if (!str_starts_with($token, '--')) {
        continue;
    }
    $key = substr($token, 2);
    $next = $args[$i + 1] ?? null;
    if ($next === null || str_starts_with($next, '--')) {
        $flags[$key] = true;
    } else {
        $flags[$key] = $next;
        $i++;
    }
}

if ($command === 'help' || $command === '--help' || $command === '-h') {
    echo json_encode([
        'package' => 'kseven/web-license-sdk',
        'version' => '1.1.0',
        'usage' => 'php bin/k7web.php <install|check-version|update|validate|entitlements|uninstall> [opções]',
        'commands' => [
            'install' => '--api <url> --key <licenseKey> --domain <host> --app-version <semver> [--platform php|wordpress|universal] [--state-file .kseven-web-license.dat] [--state-secret <secret>] [--plain-transport]',
            'check-version' => '--api <url> [--channel stable|beta] [--app-version <semver>] [--state-file ...]',
            'update' => '--api <url> [--channel stable|beta] [--dest-dir ./updates] [--state-file ...]',
            'validate' => '--api <url> [--app-version <semver>] [--state-file ...]',
            'entitlements' => '--api <url> [--state-file ...]',
            'uninstall' => '--api <url> [--reason "..."] [--state-file ...]',
        ],
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL;
    exit(0);
}

try {
    $api = (string) ($flags['api'] ?? getenv('K7_WEB_API_URL') ?: '');
    $stateFile = isset($flags['state-file']) && is_string($flags['state-file'])
        ? $flags['state-file']
        : (getenv('K7_WEB_STATE_FILE') ?: null);
    $stateSecret = isset($flags['state-secret']) && is_string($flags['state-secret'])
        ? $flags['state-secret']
        : (getenv('K7_WEB_STATE_SECRET') ?: null);
    $platform = (string) ($flags['platform'] ?? 'php');
    $allowLocal = !empty($flags['allow-local-http']) || getenv('K7_ALLOW_LOCAL_HTTP') === '1';
    $encryptTransport = empty($flags['plain-transport']) && getenv('K7_WEB_PLAIN_TRANSPORT') !== '1';

    $client = new WebLicenseClient([
        'apiBaseUrl' => $api,
        'stateFilePath' => $stateFile ?: (getcwd() . DIRECTORY_SEPARATOR . '.kseven-web-license.dat'),
        'stateSecret' => $stateSecret,
        'encryptTransport' => $encryptTransport,
        'platform' => $platform,
        'allowInsecureLocalHttp' => $allowLocal,
    ]);

    $out = match ($command) {
        'install' => $client->install([
            'licenseKey' => (string) ($flags['key'] ?? getenv('K7_WEB_LICENSE_KEY') ?: ''),
            'domain' => (string) ($flags['domain'] ?? getenv('K7_WEB_DOMAIN') ?: ''),
            'appVersion' => (string) ($flags['app-version'] ?? '1.0.0'),
            'platform' => $platform,
            'environment' => (string) ($flags['env'] ?? 'production'),
        ]),
        'check-version' => $client->checkVersion(
            (string) ($flags['channel'] ?? 'stable'),
            isset($flags['app-version']) && is_string($flags['app-version']) ? $flags['app-version'] : null
        ),
        'update' => $client->update([
            'channel' => (string) ($flags['channel'] ?? 'stable'),
            'destDir' => isset($flags['dest-dir']) && is_string($flags['dest-dir']) ? $flags['dest-dir'] : null,
        ]),
        'validate' => $client->validate(
            isset($flags['app-version']) && is_string($flags['app-version']) ? $flags['app-version'] : null
        ),
        'entitlements' => $client->entitlements(),
        'uninstall' => $client->uninstall((string) ($flags['reason'] ?? 'CLI_UNINSTALL')),
        default => throw new RuntimeException("Comando desconhecido: {$command}", 400),
    };

    echo json_encode($out, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL;
} catch (Throwable $e) {
    fwrite(STDERR, json_encode([
        'error' => true,
        'code' => $e->getCode() ?: 1,
        'message' => $e->getMessage(),
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL);
    exit(1);
}
