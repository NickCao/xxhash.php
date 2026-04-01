<?php

declare(strict_types=1);

namespace XXHash\Tests;

use PHPUnit\Framework\TestCase;
use XXHash\XXH32;
use XXHash\XXH64;
use XXHash\XXH3;
use XXHash\Math;

class XXHashTest extends TestCase
{
    private const SANITY_BUFFER_SIZE = 2367;
    private const PRIME32 = 0x9E3779B1;

    // PRIME64 = 11400714785074694797 = 0x9E3779B185EBCA8D
    private static int $PRIME64;
    private static string $sanityBuffer;

    public static function setUpBeforeClass(): void
    {
        // PRIME64 = 0x9E3779B185EBCA8D (from xsum_sanity_check.c)
        self::$PRIME64 = unpack('J', hex2bin('9E3779B185EBCA8D'))[1];

        // Generate the sanity check buffer using the PRNG from xxhash reference
        $buffer = '';
        $byteGen = self::PRIME32; // Start with PRIME32
        $prime64ForGen = self::$PRIME64;

        for ($i = 0; $i < self::SANITY_BUFFER_SIZE; $i++) {
            $buffer .= chr(Math::shr64($byteGen, 56) & 0xFF);
            $byteGen = Math::mult64($byteGen, $prime64ForGen);
        }
        self::$sanityBuffer = $buffer;
    }

    // ========================================================================
    // XXH32 test vectors
    // ========================================================================

    /** @dataProvider xxh32Provider */
    public function testXXH32(int $len, int $seed, int $expected): void
    {
        $data = substr(self::$sanityBuffer, 0, $len);
        $result = XXH32::hash($data, $seed);
        $this->assertSame(
            sprintf('%08x', $expected),
            sprintf('%08x', $result),
            "XXH32 failed for len=$len seed=" . sprintf('0x%X', $seed)
        );
    }

    /** @dataProvider xxh32Provider */
    public function testXXH32Streaming(int $len, int $seed, int $expected): void
    {
        $data = substr(self::$sanityBuffer, 0, $len);
        $h = new XXH32($seed);

        // Feed in chunks to test streaming
        $chunkSize = max(1, (int)($len / 3));
        for ($i = 0; $i < $len; $i += $chunkSize) {
            $h->update(substr($data, $i, min($chunkSize, $len - $i)));
        }

        $result = $h->digest();
        $this->assertSame(
            sprintf('%08x', $expected),
            sprintf('%08x', $result),
            "XXH32 streaming failed for len=$len"
        );
    }

    public static function xxh32Provider(): array
    {
        return [
            'empty, seed=0'       => [0,   0x00000000, 0x02CC5D05],
            'empty, seed=PRIME'   => [0,   0x9E3779B1, 0x36B78AE7],
            'len=1, seed=0'       => [1,   0x00000000, 0xCF65B03E],
            'len=1, seed=PRIME'   => [1,   0x9E3779B1, 0xB4545AA4],
            'len=14, seed=0'      => [14,  0x00000000, 0x1208E7E2],
            'len=14, seed=PRIME'  => [14,  0x9E3779B1, 0x6AF1D1FE],
            'len=222, seed=0'     => [222, 0x00000000, 0x5BD11DBD],
            'len=222, seed=PRIME' => [222, 0x9E3779B1, 0x58803C5F],
        ];
    }

    // ========================================================================
    // XXH64 test vectors
    // ========================================================================

    /** @dataProvider xxh64Provider */
    public function testXXH64(int $len, int $seed, string $expectedHex): void
    {
        $data = substr(self::$sanityBuffer, 0, $len);
        $result = XXH64::hash($data, $seed);
        $this->assertSame(
            strtolower($expectedHex),
            sprintf('%016x', $result),
            "XXH64 failed for len=$len seed=" . sprintf('0x%X', $seed)
        );
    }

    /** @dataProvider xxh64Provider */
    public function testXXH64Streaming(int $len, int $seed, string $expectedHex): void
    {
        $data = substr(self::$sanityBuffer, 0, $len);
        $h = new XXH64($seed);

        $chunkSize = max(1, (int)($len / 3));
        for ($i = 0; $i < $len; $i += $chunkSize) {
            $h->update(substr($data, $i, min($chunkSize, $len - $i)));
        }

        $this->assertSame(
            strtolower($expectedHex),
            sprintf('%016x', $h->digest()),
            "XXH64 streaming failed for len=$len"
        );
    }

    public static function xxh64Provider(): array
    {
        $p = 0x9E3779B1; // PRIME32 used as seed
        return [
            'empty, seed=0'       => [0,   0,  'EF46DB3751D8E999'],
            'empty, seed=PRIME'   => [0,   $p, 'AC75FDA2929B17EF'],
            'len=1, seed=0'       => [1,   0,  'E934A84ADB052768'],
            'len=1, seed=PRIME'   => [1,   $p, '5014607643A9B4C3'],
            'len=4, seed=0'       => [4,   0,  '9136A0DCA57457EE'],
            'len=14, seed=0'      => [14,  0,  '8282DCC4994E35C8'],
            'len=14, seed=PRIME'  => [14,  $p, 'C3BD6BF63DEB6DF0'],
            'len=222, seed=0'     => [222, 0,  'B641AE8CB691C174'],
            'len=222, seed=PRIME' => [222, $p, '20CB8AB7AE10C14A'],
        ];
    }

    // ========================================================================
    // XXH3_64bits test vectors
    // ========================================================================

    /** @dataProvider xxh3_64Provider */
    public function testXXH3_64(int $len, int $seed, string $expectedHex): void
    {
        $data = substr(self::$sanityBuffer, 0, $len);
        $result = XXH3::hash64($data, $seed);
        $this->assertSame(
            strtolower($expectedHex),
            sprintf('%016x', $result),
            "XXH3_64 failed for len=$len seed=" . sprintf('0x%X', $seed)
        );
    }

    /** @dataProvider xxh3_64Provider */
    public function testXXH3_64Streaming(int $len, int $seed, string $expectedHex): void
    {
        $data = substr(self::$sanityBuffer, 0, $len);
        $h = new XXH3($seed);

        $chunkSize = max(1, (int)($len / 7) + 1);
        for ($i = 0; $i < $len; $i += $chunkSize) {
            $h->update(substr($data, $i, min($chunkSize, $len - $i)));
        }

        $this->assertSame(
            strtolower($expectedHex),
            sprintf('%016x', $h->digest64()),
            "XXH3_64 streaming failed for len=$len"
        );
    }

    public static function xxh3_64Provider(): array
    {
        $p64 = unpack('J', hex2bin('9E3779B185EBCA8D'))[1];
        return [
            'empty, seed=0'        => [0,    0,    '2D06800538D394C2'],
            'empty, seed=PRIME64'  => [0,    $p64, 'A8A6B918B2F0364A'],
            'len=1, seed=0'        => [1,    0,    'C44BDFF4074EECDB'],
            'len=1, seed=PRIME64'  => [1,    $p64, '032BE332DD766EF8'],
            'len=6, seed=0'        => [6,    0,    '27B56A84CD2D7325'],
            'len=6, seed=PRIME64'  => [6,    $p64, '84589C116AB59AB9'],
            'len=12, seed=0'       => [12,   0,    'A713DAF0DFBB77E7'],
            'len=12, seed=PRIME64' => [12,   $p64, 'E7303E1B2336DE0E'],
            'len=24, seed=0'       => [24,   0,    'A3FE70BF9D3510EB'],
            'len=24, seed=PRIME64' => [24,   $p64, '850E80FC35BDD690'],
            'len=48, seed=0'       => [48,   0,    '397DA259ECBA1F11'],
            'len=48, seed=PRIME64' => [48,   $p64, 'ADC2CBAA44ACC616'],
            'len=80, seed=0'       => [80,   0,    'BCDEFBBB2C47C90A'],
            'len=80, seed=PRIME64' => [80,   $p64, 'C6DD0CB699532E73'],
            'len=195, seed=0'      => [195,  0,    'CD94217EE362EC3A'],
            'len=195, seed=PRIME64'=> [195,  $p64, 'BA68003D370CB3D9'],
            'len=403, seed=0'      => [403,  0,    'CDEB804D65C6DEA4'],
            'len=403, seed=PRIME64'=> [403,  $p64, '6259F6ECFD6443FD'],
            'len=512, seed=0'      => [512,  0,    '617E49599013CB6B'],
            'len=512, seed=PRIME64'=> [512,  $p64, '3CE457DE14C27708'],
            'len=2048, seed=0'     => [2048, 0,    'DD59E2C3A5F038E0'],
            'len=2048, seed=PRIME64'=>[2048, $p64, '66F81670669ABABC'],
            'len=2099, seed=0'     => [2099, 0,    'C6B9D9B3FC9AC765'],
            'len=2099, seed=PRIME64'=>[2099, $p64, '184F316843663974'],
            'len=2240, seed=0'     => [2240, 0,    '6E73A90539CF2948'],
            'len=2240, seed=PRIME64'=>[2240, $p64, '757BA8487D1B5247'],
            'len=2367, seed=0'     => [2367, 0,    'CB37AEB9E5D361ED'],
            'len=2367, seed=PRIME64'=>[2367, $p64, 'D2DB3415B942B42A'],
        ];
    }

    // ========================================================================
    // XXH3_64bits with custom secret test vectors
    // ========================================================================

    /** @dataProvider xxh3_64SecretProvider */
    public function testXXH3_64WithSecret(int $len, string $expectedHex): void
    {
        $data = substr(self::$sanityBuffer, 0, $len);
        $secret = substr(self::$sanityBuffer, 7, self::SECRET_SIZE_MIN + 11);
        $result = XXH3::hash64WithSecret($data, $secret);
        $this->assertSame(
            strtolower($expectedHex),
            sprintf('%016x', $result),
            "XXH3_64 with secret failed for len=$len"
        );
    }

    private const SECRET_SIZE_MIN = 136;

    public static function xxh3_64SecretProvider(): array
    {
        return [
            'empty'    => [0,    '3559D64878C5C66C'],
            'len=1'    => [1,    '8A52451418B2DA4D'],
            'len=6'    => [6,    '82C90AB0519369AD'],
            'len=12'   => [12,   '14631E773B78EC57'],
            'len=24'   => [24,   'CDD5542E4A9D9FE8'],
            'len=48'   => [48,   '33ABD54D094B2534'],
            'len=80'   => [80,   'E687BA1684965297'],
            'len=195'  => [195,  'A057273F5EECFB20'],
            'len=403'  => [403,  '14546019124D43B8'],
            'len=512'  => [512,  '7564693DD526E28D'],
            'len=2048' => [2048, 'D32E975821D6519F'],
            'len=2367' => [2367, '293FA8E5173BB5E7'],
        ];
    }

    // ========================================================================
    // XXH3_128bits test vectors
    // ========================================================================

    /** @dataProvider xxh3_128Provider */
    public function testXXH3_128(int $len, int $seed, string $expectedLoHex, string $expectedHiHex): void
    {
        $data = substr(self::$sanityBuffer, 0, $len);
        [$lo, $hi] = XXH3::hash128($data, $seed);
        $this->assertSame(
            strtolower($expectedLoHex),
            sprintf('%016x', $lo),
            "XXH3_128 low64 failed for len=$len seed=" . sprintf('0x%X', $seed)
        );
        $this->assertSame(
            strtolower($expectedHiHex),
            sprintf('%016x', $hi),
            "XXH3_128 high64 failed for len=$len seed=" . sprintf('0x%X', $seed)
        );
    }

    public static function xxh3_128Provider(): array
    {
        $p32 = 0x9E3779B1;
        $p64 = unpack('J', hex2bin('9E3779B185EBCA8D'))[1];
        return [
            'empty, seed=0'          => [0,    0,    '6001C324468D497F', '99AA06D3014798D8'],
            'empty, seed=PRIME32'    => [0,    $p32, '5444F7869C671AB0', '92220AE55E14AB50'],
            'len=1, seed=0'          => [1,    0,    'C44BDFF4074EECDB', 'A6CD5E9392000F6A'],
            'len=1, seed=PRIME32'    => [1,    $p32, 'B53D5557E7F76F8D', '89B99554BA22467C'],
            'len=6, seed=0'          => [6,    0,    '3E7039BDDA43CFC6', '082AFE0B8162D12A'],
            'len=6, seed=PRIME32'    => [6,    $p32, '269D8F70BE98856E', '5A865B5389ABD2B1'],
            'len=12, seed=0'         => [12,   0,    '061A192713F69AD9', '6E3EFD8FC7802B18'],
            'len=12, seed=PRIME32'   => [12,   $p32, '9BE9F9A67F3C7DFB', 'D7E09D518A3405D3'],
            'len=24, seed=0'         => [24,   0,    '1E7044D28B1B901D', '0CE966E4678D3761'],
            'len=24, seed=PRIME32'   => [24,   $p32, 'D7304C54EBAD40A9', '3162026714A6A243'],
            'len=48, seed=0'         => [48,   0,    'F942219AED80F67B', 'A002AC4E5478227E'],
            'len=48, seed=PRIME32'   => [48,   $p32, '7BA3C3E453A1934E', '163ADDE36C072295'],
            'len=81, seed=0'         => [81,   0,    '5E8BAFB9F95FB803', '4952F58181AB0042'],
            'len=81, seed=PRIME32'   => [81,   $p32, '703FBB3D7A5F755C', '2724EC7ADC750FB6'],
            'len=222, seed=0'        => [222,  0,    'F1AEBD597CEC6B3A', '337E09641B948717'],
            'len=222, seed=PRIME32'  => [222,  $p32, 'AE995BB8AF917A8D', '91820016621E97F1'],
            'len=403, seed=0'        => [403,  0,    'CDEB804D65C6DEA4', '1B6DE21E332DD73D'],
            'len=403, seed=PRIME64'  => [403,  $p64, '6259F6ECFD6443FD', 'BED311971E0BE8F2'],
            'len=512, seed=0'        => [512,  0,    '617E49599013CB6B', '18D2D110DCC9BCA1'],
            'len=512, seed=PRIME64'  => [512,  $p64, '3CE457DE14C27708', '925D06B8EC5B8040'],
            'len=2048, seed=0'       => [2048, 0,    'DD59E2C3A5F038E0', 'F736557FD47073A5'],
            'len=2048, seed=PRIME32' => [2048, $p32, '230D43F30206260B', '7FB03F7E7186C3EA'],
            'len=2240, seed=0'       => [2240, 0,    '6E73A90539CF2948', 'CCB134FBFA7CE49D'],
            'len=2240, seed=PRIME32' => [2240, $p32, 'ED385111126FBA6F', '50A1FE17B338995F'],
            'len=2367, seed=0'       => [2367, 0,    'CB37AEB9E5D361ED', 'E89C0F6FF369B427'],
            'len=2367, seed=PRIME32' => [2367, $p32, '6F5360AE69C2F406', 'D23AAE4B76C31ECB'],
        ];
    }

    // ========================================================================
    // XXH3_128bits with custom secret test vectors
    // ========================================================================

    /** @dataProvider xxh3_128SecretProvider */
    public function testXXH3_128WithSecret(int $len, string $expectedLoHex, string $expectedHiHex): void
    {
        $data = substr(self::$sanityBuffer, 0, $len);
        $secret = substr(self::$sanityBuffer, 7, self::SECRET_SIZE_MIN + 11);
        [$lo, $hi] = XXH3::hash128WithSecret($data, $secret);
        $this->assertSame(
            strtolower($expectedLoHex),
            sprintf('%016x', $lo),
            "XXH3_128 with secret low64 failed for len=$len"
        );
        $this->assertSame(
            strtolower($expectedHiHex),
            sprintf('%016x', $hi),
            "XXH3_128 with secret high64 failed for len=$len"
        );
    }

    public static function xxh3_128SecretProvider(): array
    {
        return [
            'empty'  => [0,  '005923CCEECBE8AE', '5F70F4EA232F1D38'],
            'len=1'  => [1,  '8A52451418B2DA4D', '3A66AF5A9819198E'],
            'len=6'  => [6,  '0B61C8ACA7D4778F', '376BD91B6432F36D'],
            'len=12' => [12, 'AF82F6EBA263D7D8', '90A3C2D839F57D0F'],
        ];
    }
}
