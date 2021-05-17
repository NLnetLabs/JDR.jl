using JDR.Common
using JDR.ASN1
using JDR.ASN1.ASN
using JDR.ASN1.DER
using Sockets

@testset "RFC 3779" begin
    # IPv4:
    buf = Vector{UInt8}([0x04, 0x80])
    @test bitstring_to_v4range(buf) == IPRange("128.0.0.0/4")

    buf = Vector{UInt8}([0x02, 0xB9, 0x31, 0x8C])
    @test isequal(bitstring_to_v4range(buf), IPRange("185.49.140.0/22"))

    buf = Vector{UInt8}([0x00])
    @test isequal(bitstring_to_v4range(buf), IPRange("0.0.0.0/0"))

    # IPv6:
    buf = Vector{UInt8}([0x03, 0x2A, 0x04, 0xB9, 0x00])
    @test isequal(bitstring_to_v6range(buf), IPRange("2a04:b900::/29"))

    buf = Vector{UInt8}([0x00])
    @test isequal(bitstring_to_v6range(buf), IPRange("::/0"))


    # ipAddressRange
    buf  = hex2bytes(b"068140")
    buf2 = hex2bytes(b"0480")
    ipr = bitstrings_to_v4range(buf, buf2)

    @test ipr.first == IPv4("129.64.0.0")
    @test ipr.last == IPv4("143.255.255.255")
end



# validation_common.jl tests
@testset "bitstring(s)_to_v(6|4)range" begin
    raw_min = UInt8[0x06, 0x24, 0x01, 0xf5, 0x40]
    raw_max = UInt8[0x00, 0x24, 0x01, 0xf5, 0x40, 0x00, 0x06]
    correct = "2401:f540:: .. 2401:f540:6:ffff:ffff:ffff:ffff:ffff"
    @test string(bitstrings_to_v6range(raw_min, raw_max)) == correct

    raw_min = UInt8[0x04, 0xd0, 0x7f, 0xd0] 
    raw_max = UInt8[0x03, 0xd0, 0x7f, 0xf0]
    correct = "208.127.208.0 .. 208.127.247.255"
    @test string(bitstrings_to_v4range(raw_min, raw_max)) == correct

    # 4 bytes
    raw = UInt8[0x01, 0x0a, 0x00, 0x00, 0x00]
    correct = IPRange("10.0.0.0/31")
    @test bitstring_to_v4range(raw) == correct

    # 3 bytes
    raw = UInt8[0x01, 0xb2, 0x9d, 0x58]
    correct = IPRange("178.157.88.0/23")
    @test bitstring_to_v4range(raw) == correct

    # 2 bytes
    raw = UInt8[0x07, 0x03, 0x00]
    correct = IPRange("3.0.0.0/9")
    @test bitstring_to_v4range(raw) == correct

    raw = UInt8[0x00, 0x26, 0x20, 0x00, 0x07, 0x40, 0x00]
    correct = IPRange("2620:7:4000::/48")

    @test bitstring_to_v6range(raw) == correct
end

@testset "validation_common.jl helpers" begin
    buf = hex2bytes(b"A003020102")
    tree = DER.parse_recursive(DER.Buf(buf))
    @test check_contextspecific(tree)
    @test check_contextspecific(tree, 0x00)
    @test childcount(tree, 1)
    @test check_tag(tree[1], ASN1.INTEGER)
end
