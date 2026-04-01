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
 *
 * Boundary values for 16-bit slots: 0x0000, 0x0001, 0x7FFF, 0x8000, 0xFFFF
 * Boundary values for 32-bit halves: 0x00000000, 0x00000001, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF
 */
class MathTest extends TestCase
{
    use TestTrait;

    private const RANDOM_SAMPLES = 500;

    // 16-bit slot boundary values (for mult64/mult128 decomposition)
    private const SLOT16 = [0x0000, 0x0001, 0x7FFF, 0x8000, 0xFFFF];

    // 32-bit half boundary values (for add64/sub64 decomposition)
    private const HALF32 = [0x00000000, 0x00000001, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF];

    // Representative shift amounts covering edges
    private const SHIFTS = [1, 2, 15, 16, 17, 31, 32, 33, 47, 48, 49, 62, 63];

    protected function setUp(): void
    {
        if (!extension_loaded('gmp')) {
            $this->markTestSkipped('GMP extension required');
        }
        $this->limitTo(self::RANDOM_SAMPLES);
    }

    // ========================================================================
    // Helpers
    // ========================================================================

    private static function toGmp(int $val): \GMP
    {
        if ($val >= 0) return gmp_init($val);
        return gmp_add(gmp_init($val), gmp_pow(2, 64));
    }

    private static function fromGmp(\GMP $val): int
    {
        if (gmp_cmp($val, gmp_pow(2, 63)) >= 0) {
            return gmp_intval(gmp_sub($val, gmp_pow(2, 64)));
        }
        return gmp_intval($val);
    }

    private static function mask64(\GMP $val): \GMP
    {
        return gmp_and($val, gmp_sub(gmp_pow(2, 64), 1));
    }

    /** Build a 64-bit value from four 16-bit slots */
    private static function from16(int $s3, int $s2, int $s1, int $s0): int
    {
        return ($s3 << 48) | ($s2 << 32) | ($s1 << 16) | $s0;
    }

    /** Build a 64-bit value from two 32-bit halves */
    private static function from32(int $hi, int $lo): int
    {
        return ($hi << 32) | $lo;
    }

    /** All 64-bit boundary values built from 16-bit slot combinations (5^4 = 625) */
    private static function boundary64from16(): array
    {
        $vals = [];
        foreach (self::SLOT16 as $s3) {
            foreach (self::SLOT16 as $s2) {
                foreach (self::SLOT16 as $s1) {
                    foreach (self::SLOT16 as $s0) {
                        $vals[] = self::from16($s3, $s2, $s1, $s0);
                    }
                }
            }
        }
        return $vals;
    }

    /** All 64-bit boundary values built from 32-bit half combinations (5^2 = 25) */
    private static function boundary64from32(): array
    {
        $vals = [];
        foreach (self::HALF32 as $hi) {
            foreach (self::HALF32 as $lo) {
                $vals[] = self::from32($hi, $lo);
            }
        }
        return $vals;
    }

    /** 32-bit boundary values */
    private static function boundary32(): array
    {
        return self::HALF32;
    }

    /** Generate a random 64-bit int from two 32-bit halves */
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
    // GMP oracle functions
    // ========================================================================

    private static function gmpAdd64(int $a, int $b): int
    {
        return self::fromGmp(self::mask64(gmp_add(self::toGmp($a), self::toGmp($b))));
    }

    private static function gmpSub64(int $a, int $b): int
    {
        return self::fromGmp(self::mask64(gmp_add(gmp_sub(self::toGmp($a), self::toGmp($b)), gmp_pow(2, 64))));
    }

    private static function gmpMult64(int $a, int $b): int
    {
        return self::fromGmp(self::mask64(gmp_mul(self::toGmp($a), self::toGmp($b))));
    }

    /** @return int[] [lo, hi] */
    private static function gmpMult128(int $a, int $b): array
    {
        $full = gmp_mul(self::toGmp($a), self::toGmp($b));
        return [
            self::fromGmp(self::mask64($full)),
            self::fromGmp(self::mask64(gmp_div_q($full, gmp_pow(2, 64)))),
        ];
    }

    private static function gmpRotl64(int $val, int $n): int
    {
        $g = self::toGmp($val);
        $left = self::mask64(gmp_mul($g, gmp_pow(2, $n)));
        $right = gmp_div_q($g, gmp_pow(2, 64 - $n));
        return self::fromGmp(gmp_or($left, $right));
    }

    private static function gmpShr64(int $val, int $n): int
    {
        return self::fromGmp(gmp_div_q(self::toGmp($val), gmp_pow(2, $n)));
    }

    // ========================================================================
    // add64
    // ========================================================================

    public function testAdd64Boundary(): void
    {
        $vals = self::boundary64from32();
        foreach ($vals as $a) {
            foreach ($vals as $b) {
                $this->assertSame(self::gmpAdd64($a, $b), Math::add64($a, $b),
                    sprintf("add64(0x%016x, 0x%016x)", $a, $b));
            }
        }
    }

    public function testAdd64Random(): void
    {
        $this->forAll(self::int64Gen(), self::int64Gen())
            ->then(function (int $a, int $b): void {
                $this->assertSame(self::gmpAdd64($a, $b), Math::add64($a, $b),
                    sprintf("add64(0x%016x, 0x%016x)", $a, $b));
            });
    }

    // ========================================================================
    // sub64
    // ========================================================================

    public function testSub64Boundary(): void
    {
        $vals = self::boundary64from32();
        foreach ($vals as $a) {
            foreach ($vals as $b) {
                $this->assertSame(self::gmpSub64($a, $b), Math::sub64($a, $b),
                    sprintf("sub64(0x%016x, 0x%016x)", $a, $b));
            }
        }
    }

    public function testSub64Random(): void
    {
        $this->forAll(self::int64Gen(), self::int64Gen())
            ->then(function (int $a, int $b): void {
                $this->assertSame(self::gmpSub64($a, $b), Math::sub64($a, $b),
                    sprintf("sub64(0x%016x, 0x%016x)", $a, $b));
            });
    }

    // ========================================================================
    // mult64 — most critical: uses 16-bit decomposition
    // ========================================================================

    public function testMult64Boundary(): void
    {
        // 5^4 = 625 values per operand, but 625×625 = 390K pairs is too many
        // assertions for one test. Use 25 values from 32-bit halves (25×25 = 625)
        // plus a focused set from 16-bit slots.
        $vals32 = self::boundary64from32();
        foreach ($vals32 as $a) {
            foreach ($vals32 as $b) {
                $this->assertSame(self::gmpMult64($a, $b), Math::mult64($a, $b),
                    sprintf("mult64(0x%016x, 0x%016x)", $a, $b));
            }
        }
    }

    public function testMult64Boundary16bit(): void
    {
        // Focused test: pick values that stress each 16-bit slot independently.
        // Use representative values where exactly one slot is non-zero.
        $representatives = [
            0, 1, 0xFFFF,                                               // slot 0
            0x10000, 0xFFFF0000,                                        // slot 1
            0x100000000, 0xFFFF00000000,                                // slot 2
            self::from16(1, 0, 0, 0), self::from16(0xFFFF, 0, 0, 0),   // slot 3
            // Cross-slot boundaries
            self::from16(0, 0, 0xFFFF, 0xFFFF),                         // slots 0-1 full
            self::from16(0, 0xFFFF, 0xFFFF, 0),                         // slots 1-2 full
            self::from16(0xFFFF, 0xFFFF, 0, 0),                         // slots 2-3 full
            self::from16(0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF),               // all full
            self::from16(0x8000, 0x8000, 0x8000, 0x8000),               // all midpoint
            self::from16(0x7FFF, 0x7FFF, 0x7FFF, 0x7FFF),               // all just below mid
            PHP_INT_MAX,                                                 // 0x7FFFFFFFFFFFFFFF
            PHP_INT_MIN,                                                 // 0x8000000000000000
            -1,                                                          // 0xFFFFFFFFFFFFFFFF
        ];
        foreach ($representatives as $a) {
            foreach ($representatives as $b) {
                $this->assertSame(self::gmpMult64($a, $b), Math::mult64($a, $b),
                    sprintf("mult64(0x%016x, 0x%016x)", $a, $b));
            }
        }
    }

    public function testMult64Random(): void
    {
        $this->forAll(self::int64Gen(), self::int64Gen())
            ->then(function (int $a, int $b): void {
                $this->assertSame(self::gmpMult64($a, $b), Math::mult64($a, $b),
                    sprintf("mult64(0x%016x, 0x%016x)", $a, $b));
            });
    }

    // ========================================================================
    // mult128
    // ========================================================================

    public function testMult128Boundary(): void
    {
        $vals = self::boundary64from32();
        foreach ($vals as $a) {
            foreach ($vals as $b) {
                [$eLo, $eHi] = self::gmpMult128($a, $b);
                [$aLo, $aHi] = Math::mult128($a, $b);
                $this->assertSame($eLo, $aLo, sprintf("mult128(0x%016x, 0x%016x) lo", $a, $b));
                $this->assertSame($eHi, $aHi, sprintf("mult128(0x%016x, 0x%016x) hi", $a, $b));
            }
        }
    }

    public function testMult128Random(): void
    {
        $this->forAll(self::int64Gen(), self::int64Gen())
            ->then(function (int $a, int $b): void {
                [$eLo, $eHi] = self::gmpMult128($a, $b);
                [$aLo, $aHi] = Math::mult128($a, $b);
                $this->assertSame($eLo, $aLo, sprintf("mult128(0x%016x, 0x%016x) lo", $a, $b));
                $this->assertSame($eHi, $aHi, sprintf("mult128(0x%016x, 0x%016x) hi", $a, $b));
            });
    }

    // ========================================================================
    // mul128fold64
    // ========================================================================

    public function testMul128fold64Random(): void
    {
        $this->forAll(self::int64Gen(), self::int64Gen())
            ->then(function (int $a, int $b): void {
                [$lo, $hi] = self::gmpMult128($a, $b);
                $expected = $lo ^ $hi;
                $this->assertSame($expected, Math::mul128fold64($a, $b),
                    sprintf("mul128fold64(0x%016x, 0x%016x)", $a, $b));
            });
    }

    // ========================================================================
    // mult32to64
    // ========================================================================

    public function testMult32to64Boundary(): void
    {
        $vals = self::boundary32();
        foreach ($vals as $a) {
            foreach ($vals as $b) {
                $expected = self::fromGmp(gmp_mul(gmp_init($a), gmp_init($b)));
                $this->assertSame($expected, Math::mult32to64($a, $b),
                    sprintf("mult32to64(0x%08x, 0x%08x)", $a, $b));
            }
        }
    }

    public function testMult32to64Random(): void
    {
        $this->forAll(Generator\choose(0, 0xFFFFFFFF), Generator\choose(0, 0xFFFFFFFF))
            ->then(function (int $a, int $b): void {
                $expected = self::fromGmp(gmp_mul(gmp_init($a), gmp_init($b)));
                $this->assertSame($expected, Math::mult32to64($a, $b),
                    sprintf("mult32to64(0x%08x, 0x%08x)", $a, $b));
            });
    }

    // ========================================================================
    // mult32
    // ========================================================================

    public function testMult32Boundary(): void
    {
        $vals = self::boundary32();
        foreach ($vals as $a) {
            foreach ($vals as $b) {
                $expected = gmp_intval(gmp_and(gmp_mul(gmp_init($a), gmp_init($b)), gmp_init(0xFFFFFFFF)));
                $this->assertSame($expected, Math::mult32($a, $b),
                    sprintf("mult32(0x%08x, 0x%08x)", $a, $b));
            }
        }
    }

    public function testMult32Random(): void
    {
        $this->forAll(Generator\choose(0, 0xFFFFFFFF), Generator\choose(0, 0xFFFFFFFF))
            ->then(function (int $a, int $b): void {
                $expected = gmp_intval(gmp_and(gmp_mul(gmp_init($a), gmp_init($b)), gmp_init(0xFFFFFFFF)));
                $this->assertSame($expected, Math::mult32($a, $b),
                    sprintf("mult32(0x%08x, 0x%08x)", $a, $b));
            });
    }

    // ========================================================================
    // rotl64
    // ========================================================================

    public function testRotl64Boundary(): void
    {
        $vals = self::boundary64from32();
        foreach ($vals as $val) {
            foreach (self::SHIFTS as $n) {
                $this->assertSame(self::gmpRotl64($val, $n), Math::rotl64($val, $n),
                    sprintf("rotl64(0x%016x, %d)", $val, $n));
            }
        }
    }

    public function testRotl64Random(): void
    {
        $this->forAll(self::int64Gen(), Generator\choose(1, 63))
            ->then(function (int $val, int $n): void {
                $this->assertSame(self::gmpRotl64($val, $n), Math::rotl64($val, $n),
                    sprintf("rotl64(0x%016x, %d)", $val, $n));
            });
    }

    // ========================================================================
    // rotl32
    // ========================================================================

    public function testRotl32Boundary(): void
    {
        $vals = self::boundary32();
        $shifts32 = [1, 2, 7, 8, 13, 15, 16, 17, 23, 24, 27, 31];
        foreach ($vals as $val) {
            foreach ($shifts32 as $n) {
                $g = gmp_init($val);
                $left = gmp_and(gmp_mul($g, gmp_pow(2, $n)), gmp_init(0xFFFFFFFF));
                $right = gmp_div_q($g, gmp_pow(2, 32 - $n));
                $expected = gmp_intval(gmp_or($left, $right));
                $this->assertSame($expected, Math::rotl32($val, $n),
                    sprintf("rotl32(0x%08x, %d)", $val, $n));
            }
        }
    }

    public function testRotl32Random(): void
    {
        $this->forAll(Generator\choose(0, 0xFFFFFFFF), Generator\choose(1, 31))
            ->then(function (int $val, int $n): void {
                $g = gmp_init($val);
                $left = gmp_and(gmp_mul($g, gmp_pow(2, $n)), gmp_init(0xFFFFFFFF));
                $right = gmp_div_q($g, gmp_pow(2, 32 - $n));
                $expected = gmp_intval(gmp_or($left, $right));
                $this->assertSame($expected, Math::rotl32($val, $n),
                    sprintf("rotl32(0x%08x, %d)", $val, $n));
            });
    }

    // ========================================================================
    // shr64
    // ========================================================================

    public function testShr64Boundary(): void
    {
        $vals = self::boundary64from32();
        foreach ($vals as $val) {
            foreach (self::SHIFTS as $n) {
                $this->assertSame(self::gmpShr64($val, $n), Math::shr64($val, $n),
                    sprintf("shr64(0x%016x, %d)", $val, $n));
            }
        }
    }

    public function testShr64Random(): void
    {
        $this->forAll(self::int64Gen(), Generator\choose(1, 63))
            ->then(function (int $val, int $n): void {
                $this->assertSame(self::gmpShr64($val, $n), Math::shr64($val, $n),
                    sprintf("shr64(0x%016x, %d)", $val, $n));
            });
    }

    // ========================================================================
    // xorshift64
    // ========================================================================

    public function testXorshift64Boundary(): void
    {
        $vals = self::boundary64from32();
        foreach ($vals as $val) {
            foreach (self::SHIFTS as $n) {
                $expected = $val ^ self::gmpShr64($val, $n);
                $this->assertSame($expected, Math::xorshift64($val, $n),
                    sprintf("xorshift64(0x%016x, %d)", $val, $n));
            }
        }
    }

    public function testXorshift64Random(): void
    {
        $this->forAll(self::int64Gen(), Generator\choose(1, 63))
            ->then(function (int $val, int $n): void {
                $expected = $val ^ self::gmpShr64($val, $n);
                $this->assertSame($expected, Math::xorshift64($val, $n),
                    sprintf("xorshift64(0x%016x, %d)", $val, $n));
            });
    }

    // ========================================================================
    // swap32
    // ========================================================================

    public function testSwap32Boundary(): void
    {
        foreach (self::boundary32() as $val) {
            $b0 = $val & 0xFF;
            $b1 = ($val >> 8) & 0xFF;
            $b2 = ($val >> 16) & 0xFF;
            $b3 = ($val >> 24) & 0xFF;
            $expected = ($b0 << 24) | ($b1 << 16) | ($b2 << 8) | $b3;
            $this->assertSame($expected, Math::swap32($val),
                sprintf("swap32(0x%08x)", $val));
        }
    }

    public function testSwap32Random(): void
    {
        $this->forAll(Generator\choose(0, 0xFFFFFFFF))
            ->then(function (int $val): void {
                $b0 = $val & 0xFF;
                $b1 = ($val >> 8) & 0xFF;
                $b2 = ($val >> 16) & 0xFF;
                $b3 = ($val >> 24) & 0xFF;
                $expected = ($b0 << 24) | ($b1 << 16) | ($b2 << 8) | $b3;
                $this->assertSame($expected, Math::swap32($val),
                    sprintf("swap32(0x%08x)", $val));
            });
    }

    // ========================================================================
    // swap64
    // ========================================================================

    public function testSwap64Boundary(): void
    {
        foreach (self::boundary64from32() as $val) {
            $hex = str_pad(sprintf('%016x', $val), 16, '0', STR_PAD_LEFT);
            $reversed = '';
            for ($i = 14; $i >= 0; $i -= 2) {
                $reversed .= substr($hex, $i, 2);
            }
            $expected = self::fromGmp(gmp_init($reversed, 16));
            $this->assertSame($expected, Math::swap64($val),
                sprintf("swap64(0x%016x)", $val));
        }
    }

    public function testSwap64Random(): void
    {
        $this->forAll(self::int64Gen())
            ->then(function (int $val): void {
                $hex = str_pad(sprintf('%016x', $val), 16, '0', STR_PAD_LEFT);
                $reversed = '';
                for ($i = 14; $i >= 0; $i -= 2) {
                    $reversed .= substr($hex, $i, 2);
                }
                $expected = self::fromGmp(gmp_init($reversed, 16));
                $this->assertSame($expected, Math::swap64($val),
                    sprintf("swap64(0x%016x)", $val));
            });
    }

    // ========================================================================
    // read32 / read64 roundtrip
    // ========================================================================

    public function testRead32Random(): void
    {
        $this->forAll(Generator\choose(0, 0xFFFFFFFF))
            ->then(function (int $val): void {
                $this->assertSame($val, Math::read32(pack('V', $val), 0),
                    sprintf("read32 roundtrip for 0x%08x", $val));
            });
    }

    public function testRead64Random(): void
    {
        $this->forAll(self::int64Gen())
            ->then(function (int $val): void {
                $this->assertSame($val, Math::read64(pack('P', $val), 0),
                    sprintf("read64 roundtrip for 0x%016x", $val));
            });
    }
}
