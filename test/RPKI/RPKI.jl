using JDR.RPKI
using JDR.RPKICommon

@testset "process_tas and link_resources" begin
    (tree, lookup) = RPKI.process_tas();
    RPKI.link_resources!.(tree.children);
end

@skip @testset "CER encoded manifests and ROAs" begin
    o = RPKI.check_ASN1(RPKI.RPKIObject(testdata_fn("chunked_octets_lacnic.mft")), TmpParseInfo())
    #ASN.print_node(o.tree, traverse=true, max_lines=0)
    
    o = RPKI.check_ASN1(RPKI.RPKIObject(testdata_fn("chunked_roa_lacnic.roa")), TmpParseInfo())
    #ASN.print_node(o.tree, traverse=true, max_lines=0)

    #RPKI.process_cer(testdata_fn("rta-lacnic-rpki.cer"))
end


#FIXME process_mft needs a cer_node passed...
@skip @testset "Missing files in .mft" begin
    tpi = TmpParseInfo()
    #node = RPKI.process_mft(RPKI.RPKIObject(testdata_fn("mft_missing_files/RIPE-NCC-TA-TEST.mft")), tpi)
    obj = RPKIObject(testdata_fn("mft_missing_files/RIPE-NCC-TA-TEST.mft"))

    @test  length(obj.object.missing_files) == 2

    @test "RIPE-NCC-TA-TEST.crl" in node.obj.object.missing_files 
    @test "4b63f8aeaddeb5951907764a034cff3f7d64c097.cer" in node.obj.object.missing_files 
    @test length(node.obj.remarks) > 0
end

#FIXME
@skip @testset "Loop detection" begin
    #old_env = if "JULIA_DEBUG" in keys(ENV)
    #    ENV["JULIA_DEBUG"]
    #else
    #    ""
    #end
    #ENV["JULIA_DEBUG"] = "all"
    l = Lookup()
    tpi = TmpParseInfo()
    node = RPKI.process_cer(testdata_fn("loop_afrinic/AfriNIC.cer"), l, tpi)
    mft = node.children[1].obj.object

    @test  length(mft.loops) > 2
    # FIXME: because we try to continue iterating of the filed listed in the
    # manifest, the files that are eventually listed in MFT.loops might not be
    # the complete list of loops..
    #@test "arin-to-afrinic.cer" in mft.loops
    #@test "apnic-to-afrinic.cer" in mft.loops
    #@test "ripe-to-afrinic.cer" in mft.loops
    #@test "afrinic-ca.cer" in mft.loops
    #@test "lacnic-to-afrinic.cer" in mft.loops
    #ENV["JULIA_DEBUG"] = old_env
end
