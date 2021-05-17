using JDR.ASN1
using JDR.RPKI
using JDR.PKIX
using JDR.RPKICommon
using JDR.Common


@testset "CMS message digest" begin
    file = testdata_fn("97045a49-c16c-3f36-994f-16efb9ea8bfc.roa")
    res = DER.parse_file_recursive(file)
    obj = RPKIObject(file)
    tpi = TmpParseInfo(; nicenames=true)
    res = RPKI.check_ASN1(obj, tpi)

    #TODO @test res.cms_valid == true
end

@testset "ROA check_ASN1" begin
    file = testdata_fn("NBtjrUUtyCdS0W9TWLl18YKJznQ.roa")
    obj = RPKIObject(file)
    tpi = TmpParseInfo(; nicenames=true)
    obj = RPKI.check_ASN1(obj, tpi)
    roa = obj.object
    @test roa.asid == 205844

    expected = [IPRange("178.157.88.0/23") , IPRange("185.204.128.0/22")]
    vrps = map(e -> IPRange(e.first, e.last), collect(roa.vrp_tree.resources_v4))
    @test issetequal(expected, vrps)
end
