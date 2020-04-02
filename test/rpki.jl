@testset "Object checks" begin
    file = testdata_fn("ripe-ncc-ta.cer")
    file = testdata_fn("nlnetlabs.cer")
    file = testdata_fn("arin-rpki-ta.cer")
    file = testdata_fn("lacnic_ipaddressrange.cer")
    file = testdata_fn("lacnic_ipaddressrange_v6.cer")
    #file = testdata_fn("lacnic_broken.mft")
    #file = testdata_fn("lacnic_ok.mft")
    #file = testdata_fn("ripe-ncc-ta.mft")
    #file = testdata_fn("NBtjrUUtyCdS0W9TWLl18YKJznQ.roa")
    r = RPKI.RPKIObject(file)
    o = RPKI.check(r)
    #ASN.print_node(r.tree, traverse=true, max_lines=0)
    #@test isequal(length( #TODO implement get_all_remarks, check length == 0
end

@testset "CER encoded manifests and ROAs" begin
    o = RPKI.check(RPKI.RPKIObject(testdata_fn("chunked_octets_lacnic.mft")))
    #ASN.print_node(o.tree, traverse=true, max_lines=0)
    
    o = RPKI.check(RPKI.RPKIObject(testdata_fn("chunked_roa_lacnic.roa")))
    #ASN.print_node(o.tree, traverse=true, max_lines=0)

    #RPKI.process_cer(testdata_fn("rta-lacnic-rpki.cer"))
end


@testset "Retrieve all" begin
    (tree, lookup) = RPKI.retrieve_all();
    #RPKI.html(tree, "/tmp/rpki.html")
end


@testset "Missing files in .mft" begin
    l = RPKI.Lookup()
    node = RPKI.process_mft(testdata_fn("mft_missing_files/RIPE-NCC-TA-TEST.mft"), l)
    @test  length(node.obj.object.missing_files) == 2
    @test "RIPE-NCC-TA-TEST.crl" in node.obj.object.missing_files 
    @test "4b63f8aeaddeb5951907764a034cff3f7d64c097.cer" in node.obj.object.missing_files 
    @test length(node.obj.remarks) > 0
end

@testset "Counting remarks" begin
    o = RPKI.check(RPKI.RPKIObject(testdata_fn("ripe-ncc-ta.mft")))
    #@debug ASN.count_remarks(o.tree)
    m = RPKI.process_cer(testdata_fn("ripe-ncc-ta.cer"), RPKI.Lookup())
    #@debug "process_cer done, now counting remarks"
    remark_cnt = RPKI.count_remarks(m)
    #@debug remark_cnt
                         
end



# for debugging individual files:

@skip @testset "Individual file debugging" begin
    file = testdata_fn("afrinic.mft")
    @debug "parsing $(file)"
    @time tree = DER.parse_file_recursive(file)
    ASN.print_node(tree, traverse=true)
end

