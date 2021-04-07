using Sockets: IPv6, IPv4
using JDR.Common

@testset "IPRange" begin

    # IPv6
    
    ipr = IPRange("2001:db8::/32")
    @test ipr isa IPRange{IPv6}
    @test prefixlen(ipr) == 32

    ipr = IPRange("::/0")
    @test ipr isa IPRange{IPv6}
    @test length(ipr) == typemax(UInt128)
    @test prefixlen(ipr) == 0 

    ipr = IPRange("2001:db8::1/128")
    @test ipr isa IPRange{IPv6}
    @test length(ipr) == 1

    ipr = IPRange(IPv6("2001::10:1"), IPv6("2001::10:a"))
    @test length(ipr) == 10

    # IPv4

    ipr = IPRange("1.2.3.0/24")
    @test ipr isa IPRange{IPv4}
    @test prefixlen(ipr) == 24

    ipr = IPRange("0/0")
    @test ipr isa IPRange{IPv4}
    @test prefixlen(ipr) == 0 

    ipr = IPRange("1.1.1.1/32")
    @test ipr isa IPRange{IPv4}
    @test length(ipr) == 1

    ipr = IPRange(IPv4("1.2.3.1"), IPv4("1.2.3.10"))
    @test length(ipr) == 10

end
