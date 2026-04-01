<?php

declare(strict_types=1);

namespace XXHash\Tests;

use Eris\Generator;
use Eris\TestTrait;
use PHPUnit\Framework\TestCase;
use XXHash\Math;

/**
 * Exhaustive boundary + random sampling tests for Math primitives,
 * verified against GMP as oracle.
 */
class MathTest extends TestCase
{
    use TestTrait;

    private const RANDOM_SAMPLES = 500;

    protected function setUp(): void
    {
        $this->limitTo(self::RANDOM_SAMPLES);
    }

    // ========================================================================
    // Helpers: GMP oracle for unsigned 64-bit arithmetic
    // ========================================================================

    private static function toGmp(int $val): \GMP
    {
        // Convert signed PHP int to unsigned GMP value
        if ($val >= 0) return gmp_init($val);
        return gmp_add(gmp_init($val), gmp_pow(2, 64));
    }

    private static function fromGmp(\GMP $val): int
    {
        // Convert unsigned GMP value to signed PHP int (same bit pattern)
        if (gmp_cmp($val, gmp_pow(2, 63)) >= 0) {
            return gmp_intval(gmp_sub($val, gmp_pow(2, 64)));
        }
        return gmp_intval($val);
    }

    private static function mask64(\GMP $val): \GMP
    {
        return gmp_and($val, gmp_sub(gmp_pow(2, 64), 1));
    }

    /** Generate a 64-bit int from two 32-bit halves */
    private static function int64Gen(): Generator
    {
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
    // add64
    // ========================================================================

    public function testAdd64Random(): void
    {
        $this->forAll(self::int64Gen(), self::int64Gen())
            ->then(function (int $a, int $b): void {
                $expected = self::fromGmp(self::mask64(gmp_add(self::toGmp($a), self::toGmp($b))));
                $actual = Math::add64($a, $b);
                $this->assertSame($expected, $actual,
                    sprintf("add64(0x%016x, 0x%016x)", $a, $b));
            });
    }

    // ========================================================================
    // sub64
    // ========================================================================

    public function testSub64Random(): void
    {
        $this->forAll(self::int64Gen(), self::int64Gen())
            ->then(function (int $a, int $b): void {
                $expected = self::fromGmp(self::mask64(gmp_add(gmp_sub(self::toGmp($a), self::toGmp($b)), gmp_pow(2, 64))));
                $actual = Math::sub64($a, $b);
                $this->assertSame($expected, $actual,
                    sprintf("sub64(0x%016x, 0x%016x)", $a, $b));
            });
    }

    // ========================================================================
    // mult64
    // ========================================================================

    public function testMult64Random(): void
    {
        $this->forAll(self::int64Gen(), self::int64Gen())
            ->then(function (int $a, int $b): void {
                $expected = self::fromGmp(self::mask64(gmp_mul(self::toGmp($a), self::toGmp($b))));
                $actual = Math::mult64($a, $b);
                $this->assertSame($expected, $actual,
                    sprintf("mult64(0x%016x, 0x%016x)", $a, $b));
            });
    }

    // ========================================================================
    // mult128
    // ========================================================================

    public function testMult128Random(): void
    {
        $this->forAll(self::int64Gen(), self::int64Gen())
            ->then(function (int $a, int $b): void {
                $full = gmp_mul(self::toGmp($a), self::toGmp($b));
                $expectedLo = self::fromGmp(self::mask64($full));
                $expectedHi = self::fromGmp(self::mask64(gmp_div_q($full, gmp_pow(2, 64))));

                [$actualLo, $actualHi] = Math::mult128($a, $b);
                $this->assertSame($expectedLo, $actualLo,
                    sprintf("mult128(0x%016x, 0x%016x) low64", $a, $b));
                $this->assertSame($expectedHi, $actualHi,
                    sprintf("mult128(0x%016x, 0x%016x) high64", $a, $b));
            });
    }

    // ========================================================================
    // mul128fold64
    // ========================================================================

    public function testMul128fold64Random(): void
    {
        $this->forAll(self::int64Gen(), self::int64Gen())
            ->then(function (int $a, int $b): void {
                $full = gmp_mul(self::toGmp($a), self::toGmp($b));
                $lo = self::mask64($full);
                $hi = self::mask64(gmp_div_q($full, gmp_pow(2, 64)));
                $expected = self::fromGmp(gmp_xor($lo, $hi));

                $actual = Math::mul128fold64($a, $b);
                $this->assertSame($expected, $actual,
                    sprintf("mul128fold64(0x%016x, 0x%016x)", $a, $b));
            });
    }

    // ========================================================================
    // mult32to64
    // ========================================================================

    public function testMult32to64Random(): void
    {
        $this->forAll(Generator\choose(0, 0xFFFFFFFF), Generator\choose(0, 0xFFFFFFFF))
            ->then(function (int $a, int $b): void {
                $expected = self::fromGmp(gmp_mul(gmp_init($a), gmp_init($b)));
                $actual = Math::mult32to64($a, $b);
                $this->assertSame($expected, $actual,
                    sprintf("mult32to64(0x%08x, 0x%08x)", $a, $b));
            });
    }

    // ========================================================================
    // mult32
    // ========================================================================

    public function testMult32Random(): void
    {
        $this->forAll(Generator\choose(0, 0xFFFFFFFF), Generator\choose(0, 0xFFFFFFFF))
            ->then(function (int $a, int $b): void {
                $expected = gmp_intval(gmp_and(gmp_mul(gmp_init($a), gmp_init($b)), gmp_init(0xFFFFFFFF)));
                $actual = Math::mult32($a, $b);
                $this->assertSame($expected, $actual,
                    sprintf("mult32(0x%08x, 0x%08x)", $a, $b));
            });
    }

    // ========================================================================
    // rotl64
    // ========================================================================

    public function testRotl64Random(): void
    {
        $this->forAll(self::int64Gen(), Generator\choose(1, 63))
            ->then(function (int $val, int $n): void {
                $g = self::toGmp($val);
                $left = self::mask64(gmp_mul($g, gmp_pow(2, $n)));
                $right = gmp_div_q($g, gmp_pow(2, 64 - $n));
                $expected = self::fromGmp(gmp_or($left, $right));

                $actual = Math::rotl64($val, $n);
                $this->assertSame($expected, $actual,
                    sprintf("rotl64(0x%016x, %d)", $val, $n));
            });
    }

    // ========================================================================
    // rotl32
    // ========================================================================

    public function testRotl32Random(): void
    {
        $this->forAll(Generator\choose(0, 0xFFFFFFFF), Generator\choose(1, 31))
            ->then(function (int $val, int $n): void {
                $g = gmp_init($val);
                $left = gmp_and(gmp_mul($g, gmp_pow(2, $n)), gmp_init(0xFFFFFFFF));
                $right = gmp_div_q($g, gmp_pow(2, 32 - $n));
                $expected = gmp_intval(gmp_or($left, $right));

                $actual = Math::rotl32($val, $n);
                $this->assertSame($expected, $actual,
                    sprintf("rotl32(0x%08x, %d)", $val, $n));
            });
    }

    // ========================================================================
    // shr64 (logical right shift)
    // ========================================================================

    public function testShr64Random(): void
    {
        $this->forAll(self::int64Gen(), Generator\choose(1, 63))
            ->then(function (int $val, int $n): void {
                $expected = self::fromGmp(gmp_div_q(self::toGmp($val), gmp_pow(2, $n)));
                $actual = Math::shr64($val, $n);
                $this->assertSame($expected, $actual,
                    sprintf("shr64(0x%016x, %d)", $val, $n));
            });
    }

    // ========================================================================
    // xorshift64
    // ========================================================================

    public function testXorshift64Random(): void
    {
        $this->forAll(self::int64Gen(), Generator\choose(1, 63))
            ->then(function (int $val, int $n): void {
                $g = self::toGmp($val);
                $shifted = gmp_div_q($g, gmp_pow(2, $n));
                $expected = self::fromGmp(gmp_xor($g, $shifted));

                $actual = Math::xorshift64($val, $n);
                $this->assertSame($expected, $actual,
                    sprintf("xorshift64(0x%016x, %d)", $val, $n));
            });
    }

    // ========================================================================
    // swap32
    // ========================================================================

    public function testSwap32Random(): void
    {
        $this->forAll(Generator\choose(0, 0xFFFFFFFF))
            ->then(function (int $val): void {
                $b0 = $val & 0xFF;
                $b1 = ($val >> 8) & 0xFF;
                $b2 = ($val >> 16) & 0xFF;
                $b3 = ($val >> 24) & 0xFF;
                $expected = ($b0 << 24) | ($b1 << 16) | ($b2 << 8) | $b3;

                $actual = Math::swap32($val);
                $this->assertSame($expected, $actual,
                    sprintf("swap32(0x%08x)", $val));
            });
    }

    // ========================================================================
    // swap64
    // ========================================================================

    public function testSwap64Random(): void
    {
        $this->forAll(self::int64Gen())
            ->then(function (int $val): void {
                // Byte-reverse using GMP
                $hex = str_pad(sprintf('%016x', $val), 16, '0', STR_PAD_LEFT);
                $reversed = '';
                for ($i = 14; $i >= 0; $i -= 2) {
                    $reversed .= substr($hex, $i, 2);
                }
                $expected = self::fromGmp(gmp_init($reversed, 16));

                $actual = Math::swap64($val);
                $this->assertSame($expected, $actual,
                    sprintf("swap64(0x%016x)", $val));
            });
    }

    // ========================================================================
    // read32 / read64
    // ========================================================================

    public function testRead32Random(): void
    {
        $this->forAll(Generator\choose(0, 0xFFFFFFFF))
            ->then(function (int $val): void {
                $data = pack('V', $val);
                $actual = Math::read32($data, 0);
                $this->assertSame($val, $actual,
                    sprintf("read32 roundtrip for 0x%08x", $val));
            });
    }

    public function testRead64Random(): void
    {
        $this->forAll(self::int64Gen())
            ->then(function (int $val): void {
                $data = pack('P', $val);
                $actual = Math::read64($data, 0);
                $this->assertSame($val, $actual,
                    sprintf("read64 roundtrip for 0x%016x", $val));
            });
    }
}
