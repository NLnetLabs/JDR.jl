using JDR.Common

@testset "macro" begin
    @test hex2bytes("2A864886F70D01010B") ==  @oid("1.2.840.113549.1.1.11")
end

@testset "split_scheme_uri" begin
    @test ("some.domain.tld", "and/module") ==  split_scheme_uri("rsync://some.domain.tld/and/module")
    @test ("some.domain.tld", "and/path") ==  split_scheme_uri("https://some.domain.tld/and/path")
end

@testset "oid to str" begin
    raw = hex2bytes("883703")
    @assert oid_to_str(raw) == "2.999.3"

    raw = UInt8[0x55, 0x1d, 0x0e]
    @assert oid_to_str(raw) == "2.5.29.14"
end


@testset "ASN / AutSysNum" begin
    @test string(AutSysNum(123)) == "AS123"
    @test string(AutSysNumRange(123,456)) == "AS123..AS456"

    @test AutSysNumRange(10, 20) == AutSysNumRange(AutSysNum(10), AutSysNum(20))


    @test covered(AutSysNum(500), AutSysNumRange(100, 1000))
    @test ! covered(AutSysNum(5000), AutSysNumRange(100, 1000))

    resources = AsIdsOrRanges()
    push!(resources, AutSysNum(100))
    push!(resources, AutSysNum(200))
    push!(resources, AutSysNumRange(500, 600))

    @test covered(AutSysNum(100), resources)
    @test covered(AutSysNum(200), resources)
    @test covered(AutSysNum(550), resources)
    @test !covered(AutSysNum(150), resources)
    @test !covered(AutSysNum(650), resources)

    sub_resources = AsIdsOrRanges()
    push!(sub_resources, AutSysNum(100))
    @test covered(sub_resources, resources)

    push!(sub_resources, AutSysNumRange(550, 600))
    @test covered(sub_resources, resources)

    push!(sub_resources, AutSysNumRange(575, 625))
    @test !covered(sub_resources, resources)
end

