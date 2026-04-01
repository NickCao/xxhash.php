<?php

declare(strict_types=1);

namespace XXHash\Tests;

use Eris\Generator;
use Eris\TestTrait;
use PHPUnit\Framework\TestCase;
use XXHash\XXH32;
use XXHash\XXH64;
use XXHash\XXH3;

/**
 * Property-based fuzz tests comparing the pure PHP implementation
 * against PHP 8's builtin xxhash (via hash() / hash_init()).
 */
class XXHashFuzzTest extends TestCase
{
    use TestTrait;

    private const ITERATIONS = 500;

    protected function setUp(): void
    {
        $this->limitTo(self::ITERATIONS);
    }

    // ========================================================================
    // Generators
    // ========================================================================

    /** Binary strings biased toward lengths that exercise all code paths */
    private static function hashInput(): Generator
    {
        // Lengths chosen to cover all xxhash internal paths:
        //   0, 1-3, 4-8, 9-16, 17-32, 33-64, 65-96, 97-128,
        //   129-240, 241-512, 513-2048
        return Generator\bind(
            Generator\oneOf(
                Generator\constant(0),
                Generator\choose(1, 3),
                Generator\choose(4, 8),
                Generator\choose(9, 16),
                Generator\choose(17, 128),
                Generator\choose(129, 240),
                Generator\choose(241, 512),
                Generator\choose(513, 2048)
            ),
            function (int $len): Generator {
                if ($len === 0) {
                    return Generator\constant('');
                }
                return Generator\map(
                    function (array $bytes) {
                        return implode('', array_map('chr', $bytes));
                    },
                    Generator\tuple(...array_fill(0, $len, Generator\choose(0, 255)))
                );
            }
        );
    }

    private static function seed32(): Generator
    {
        return Generator\oneOf(
            Generator\constant(0),
            Generator\choose(0, 0xFFFFFFFF)
        );
    }

    private static function seed64(): Generator
    {
        // Generate 64-bit seeds as two 32-bit halves combined
        return Generator\map(
            function (array $parts): int {
                return ($parts[0] << 32) | $parts[1];
            },
            Generator\tuple(
                Generator\choose(0, 0xFFFFFFFF),
                Generator\choose(0, 0xFFFFFFFF)
            )
        );
    }

    // ========================================================================
    // XXH32: pure PHP == builtin
    // ========================================================================

    public function testXXH32MatchesBuiltin(): void
    {
        $this->forAll(self::hashInput(), self::seed32())
            
            ->then(function (string $data, int $seed): void {
                $ctx = hash_init('xxh32', options: ['seed' => $seed]);
                hash_update($ctx, $data);
                $expected = hash_final($ctx);
                $actual = sprintf('%08x', XXH32::hash($data, $seed));
                $this->assertSame($expected, $actual,
                    "XXH32 mismatch for len=" . strlen($data) . " seed=$seed");
            });
    }

    // ========================================================================
    // XXH64: pure PHP == builtin
    // ========================================================================

    public function testXXH64MatchesBuiltin(): void
    {
        $this->forAll(self::hashInput(), self::seed64())
            
            ->then(function (string $data, int $seed): void {
                $ctx = hash_init('xxh64', options: ['seed' => $seed]);
                hash_update($ctx, $data);
                $expected = hash_final($ctx);
                $actual = sprintf('%016x', XXH64::hash($data, $seed));
                $this->assertSame($expected, $actual,
                    "XXH64 mismatch for len=" . strlen($data) . " seed=$seed");
            });
    }

    // ========================================================================
    // XXH3_64: pure PHP == builtin
    // ========================================================================

    public function testXXH3_64MatchesBuiltin(): void
    {
        $this->forAll(self::hashInput(), self::seed64())
            
            ->then(function (string $data, int $seed): void {
                $ctx = hash_init('xxh3', options: ['seed' => $seed]);
                hash_update($ctx, $data);
                $expected = hash_final($ctx);
                $actual = sprintf('%016x', XXH3::hash64($data, $seed));
                $this->assertSame($expected, $actual,
                    "XXH3_64 mismatch for len=" . strlen($data) . " seed=$seed");
            });
    }

    // ========================================================================
    // XXH3_128: pure PHP == builtin
    // ========================================================================

    public function testXXH3_128MatchesBuiltin(): void
    {
        $this->forAll(self::hashInput(), self::seed64())
            
            ->then(function (string $data, int $seed): void {
                $ctx = hash_init('xxh128', options: ['seed' => $seed]);
                hash_update($ctx, $data);
                $expected = hash_final($ctx);  // returns high64 || low64
                [$lo, $hi] = XXH3::hash128($data, $seed);
                $actual = sprintf('%016x%016x', $hi, $lo);
                $this->assertSame($expected, $actual,
                    "XXH3_128 mismatch for len=" . strlen($data) . " seed=$seed");
            });
    }

    // ========================================================================
    // Streaming == one-shot (random chunking)
    // ========================================================================

    public function testXXH32StreamingMatchesOneShot(): void
    {
        $this->forAll(self::hashInput(), self::seed32())
            
            ->then(function (string $data, int $seed): void {
                $expected = XXH32::hash($data, $seed);
                $h = new XXH32($seed);
                foreach (self::randomChunks($data) as $chunk) {
                    $h->update($chunk);
                }
                $this->assertSame($expected, $h->digest(),
                    "XXH32 streaming mismatch for len=" . strlen($data));
            });
    }

    public function testXXH64StreamingMatchesOneShot(): void
    {
        $this->forAll(self::hashInput(), self::seed64())
            
            ->then(function (string $data, int $seed): void {
                $expected = XXH64::hash($data, $seed);
                $h = new XXH64($seed);
                foreach (self::randomChunks($data) as $chunk) {
                    $h->update($chunk);
                }
                $this->assertSame($expected, $h->digest(),
                    "XXH64 streaming mismatch for len=" . strlen($data));
            });
    }

    public function testXXH3_64StreamingMatchesOneShot(): void
    {
        $this->forAll(self::hashInput(), self::seed64())
            
            ->then(function (string $data, int $seed): void {
                $expected = XXH3::hash64($data, $seed);
                $h = new XXH3($seed);
                foreach (self::randomChunks($data) as $chunk) {
                    $h->update($chunk);
                }
                $this->assertSame($expected, $h->digest64(),
                    "XXH3_64 streaming mismatch for len=" . strlen($data));
            });
    }

    public function testXXH3_128StreamingMatchesOneShot(): void
    {
        $this->forAll(self::hashInput(), self::seed64())
            
            ->then(function (string $data, int $seed): void {
                $expected = XXH3::hash128($data, $seed);
                $h = new XXH3($seed);
                foreach (self::randomChunks($data) as $chunk) {
                    $h->update($chunk);
                }
                $this->assertSame($expected, $h->digest128(),
                    "XXH3_128 streaming mismatch for len=" . strlen($data));
            });
    }

    // ========================================================================
    // Helper
    // ========================================================================

    /** Split string into random-sized chunks */
    private static function randomChunks(string $data): array
    {
        $len = strlen($data);
        if ($len === 0) return [''];
        $chunks = [];
        $pos = 0;
        while ($pos < $len) {
            $size = random_int(1, max(1, $len - $pos));
            $chunks[] = substr($data, $pos, $size);
            $pos += $size;
        }
        return $chunks;
    }
}
