<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAdvisories\Tests\Support;

use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * Valtry's Advisory API, faked from the same recorded feeds the public
 * sources read (tests/fixtures), and signed with a keypair made per test.
 * $tamper lets a test break the answer in one specific way.
 */
final class ValtryServer
{
    public const URL = 'https://valtry.test/api/advisories/v1/query';

    public string $publicKey;

    /** @var non-empty-string */
    private string $secretKey;

    /** @var array<string, list<array<string, mixed>>> */
    private array $data;

    /** @var list<string> Ecosystems to report as stale */
    public array $stale = [];

    /** @var (callable(array<string, mixed>, string): array{0: string, 1: string})|null Gets the answer and the nonce, returns [body, signature header] */
    public $tamper = null;

    /** @var list<array<mixed>> Decoded request bodies */
    public array $received = [];

    public function __construct(private readonly MockClient $client)
    {
        $pair = sodium_crypto_sign_keypair();
        $this->secretKey = sodium_crypto_sign_secretkey($pair);
        $this->publicKey = base64_encode(sodium_crypto_sign_publickey($pair));
        $this->data = self::dataset();
    }

    /**
     * @return array<string, string> The pinned keys a client should use
     */
    public function keys(): array
    {
        return ['test-1' => $this->publicKey];
    }

    public function respond(RequestInterface $request): ResponseInterface
    {
        $body = json_decode((string) $request->getBody(), true);
        $body = is_array($body) ? $body : [];
        $this->received[] = $body;
        $packages = is_array($body['packages'] ?? null) ? $body['packages'] : [];

        $advisories = [];
        foreach ($packages as $p) {
            $key = $p['ecosystem'].':'.$p['name'];
            $advisories[$key] = $this->data[$key] ?? [];
        }

        $answer = [
            'v' => 1,
            'generated_at' => gmdate('Y-m-d\TH:i:s\Z'),
            'nonce' => $body['nonce'] ?? null,
            'advisories' => (object) $advisories,
            'sources' => [],
            'stale' => $this->stale !== [],
            'stale_sources' => [],
            'stale_ecosystems' => $this->stale,
        ];

        $json = (string) json_encode($answer, JSON_UNESCAPED_SLASHES);
        $header = $this->sign($json);

        if ($this->tamper !== null) {
            [$json, $header] = ($this->tamper)($answer, $json);
        }

        return $this->client->json($json)->withHeader('X-Valtry-Signature', $header);
    }

    public function sign(string $body, string $kid = 'test-1'): string
    {
        return 'ed25519='.base64_encode(sodium_crypto_sign_detached($body, $this->secretKey)).'; kid='.$kid;
    }

    /**
     * What Valtry would serve for the fixtures: Packagist records as they
     * are, OSV records with their ranges written as Composer constraints,
     * and the KEV verdict on each.
     *
     * @return array<string, list<array<string, mixed>>>
     */
    public static function dataset(): array
    {
        $dir = __DIR__.'/../fixtures';
        $kev = [];
        foreach (json_decode((string) file_get_contents($dir.'/kev.json'), true)['vulnerabilities'] as $entry) {
            $kev[strtoupper($entry['cveID'])] = $entry;
        }
        $kevFor = function (?string $cve) use ($kev): array {
            $entry = $cve !== null ? ($kev[strtoupper($cve)] ?? null) : null;

            return [$entry !== null, $entry === null ? null : [
                'cve' => strtoupper($entry['cveID']),
                'name' => $entry['vulnerabilityName'],
                'date_added' => $entry['dateAdded'],
                'due_date' => $entry['dueDate'] ?? null,
                'ransomware' => strtolower($entry['knownRansomwareCampaignUse'] ?? '') === 'known',
            ]];
        };

        $data = [];
        foreach (json_decode((string) file_get_contents($dir.'/packagist.json'), true)['advisories'] as $name => $list) {
            foreach ($list as $a) {
                [$exploited, $entry] = $kevFor($a['cve'] ?? null);
                $data['composer:'.strtolower($name)][] = [
                    'id' => $a['advisoryId'], 'source' => 'packagist', 'title' => $a['title'], 'link' => $a['link'],
                    'cve' => $a['cve'] ?? null, 'aliases' => [], 'severity' => $a['severity'] ?? null,
                    'affected' => $a['affectedVersions'], 'fixed_in' => [], 'exploited' => $exploited, 'kev' => $entry,
                    'published_at' => str_replace(' ', 'T', (string) $a['reportedAt']).'Z', 'updated_at' => null, 'attribution' => null,
                ];
            }
        }

        foreach (glob($dir.'/osv/*.json') ?: [] as $file) {
            $r = json_decode((string) file_get_contents($file), true);
            $cve = null;
            foreach ([$r['id'], ...($r['aliases'] ?? [])] as $alias) {
                if (preg_match('/^CVE-\d{4}-\d+$/i', $alias) === 1) {
                    $cve = strtoupper($alias);
                    break;
                }
            }
            $groups = [];
            foreach ($r['affected'] as $a) {
                foreach ($a['ranges'] ?? [] as $range) {
                    $from = null;
                    foreach ($range['events'] as $event) {
                        if (isset($event['introduced'])) {
                            $from = $event['introduced'];
                        } elseif (isset($event['fixed']) && $from !== null) {
                            $groups[strtolower($a['package']['name'])][] = ($from === '0' ? '' : '>='.$from.',').'<'.$event['fixed'];
                            $from = null;
                        }
                    }
                }
            }
            [$exploited, $entry] = $kevFor($cve);
            foreach ($groups as $name => $parts) {
                $data['npm:'.$name][] = [
                    'id' => $r['id'], 'source' => 'osv', 'title' => $r['summary'] ?? $r['id'],
                    'link' => 'https://github.com/advisories/'.$r['id'], 'cve' => $cve, 'aliases' => $r['aliases'] ?? [],
                    'severity' => strtolower($r['database_specific']['severity'] ?? ''), 'affected' => implode('|', $parts), 'fixed_in' => [],
                    'exploited' => $exploited, 'kev' => $entry, 'published_at' => $r['published'], 'updated_at' => $r['modified'], 'attribution' => null,
                ];
            }
        }

        return $data;
    }
}
