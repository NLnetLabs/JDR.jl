using IPNets
using Sockets

@testset "RFC 3779" begin
    # IPv4:
    buf = Vector{UInt8}([0x04, 0x80])
    @test isequal(RPKI.bitstring_to_v4prefix(buf), IPv4Net("128.0.0.0/4"))

    buf = Vector{UInt8}([0x02, 0xB9, 0x31, 0x8C])
    @test isequal(RPKI.bitstring_to_v4prefix(buf), IPv4Net("185.49.140.0/22"))

    buf = Vector{UInt8}([0x00])
    @test isequal(RPKI.bitstring_to_v4prefix(buf), IPv4Net("0.0.0.0/0"))

    # IPv6:
    buf = Vector{UInt8}([0x03, 0x2A, 0x04, 0xB9, 0x00])
    @test isequal(RPKI.bitstring_to_v6prefix(buf), IPv6Net("2a04:b900::/29"))

    buf = Vector{UInt8}([0x00])
    @test isequal(RPKI.bitstring_to_v6prefix(buf), IPv6Net("::/0"))


    # ipAddressRange
    buf  = hex2bytes(b"068140")
    buf2 = hex2bytes(b"0480")
    (minaddr, maxaddr) = RPKI.bitstrings_to_v4range(buf, buf2)

    @test isequal(minaddr, IPv4Net("129.64.0.0/32"))
    @test isequal(maxaddr, IPv4Net("143.255.255.255/32"))
end


@testset "Interval-implementation RFC 3779" begin
    # IPv4:
    buf = Vector{UInt8}([0x04, 0x80])
    subnet = IPv4Net("128.0.0.0/4")
    @test isequal(RPKI.new_bitstring_to_v4prefix(buf), (Integer(subnet.netaddr), Integer(subnet[end])))

    buf = Vector{UInt8}([0x02, 0xB9, 0x31, 0x8C])
    subnet = IPv4Net("185.49.140.0/22")
    @test isequal(RPKI.new_bitstring_to_v4prefix(buf), (Integer(subnet.netaddr), Integer(subnet[end])))

    buf = Vector{UInt8}([0x00])
    subnet = IPv4Net("0.0.0.0/0")
    @test isequal(RPKI.new_bitstring_to_v4prefix(buf), (0, Integer(ip"255.255.255.255")))


    # IPv6:
    buf = Vector{UInt8}([0x03, 0x2A, 0x04, 0xB9, 0x00])
    prefix = IPv6Net("2a04:b900::/29")
    @test isequal(RPKI.new_bitstring_to_v6prefix(buf), (Integer(prefix.netaddr), Integer(prefix[end])))

    buf = Vector{UInt8}([0x00])
    prefix = IPv6Net("::/0")
    @test isequal(RPKI.new_bitstring_to_v6prefix(buf), (Integer(prefix.netaddr), Integer(ip"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")))
   

    # ipAddressRange
    buf  = hex2bytes(b"068140")
    buf2 = hex2bytes(b"0480")
    (minaddr, maxaddr) = RPKI.new_bitstrings_to_v4range(buf, buf2)

    @test isequal(minaddr, Integer(IPv4Net("129.64.0.0/32").netaddr))
    @test isequal(maxaddr, Integer(IPv4Net("143.255.255.255/32").netaddr))


end
