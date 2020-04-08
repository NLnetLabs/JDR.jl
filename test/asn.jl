println("testing $(@__FILE__)")

using JDR.ASN

@skip @testset "ASN" begin
    l1  = Leaf("leaf 1")
    l2  = Leaf("leaf 2")
    root = Node(nothing, [], "root")
    seq1 = Node(root, [l1, l2], "SEQ1")
    seq2 = Node(root, [l1, l2], "SEQ2")

    ASN.append!(root, seq1)
    ASN.append!(root, seq2)
    ASN.append!(seq2, seq1)
    #print_node(root, traverse=true)
    #println("--")
    #print_node(seq2, traverse=true)
    #println("--")
    #print_node(ASN.parent(seq1))
    #print_node(seq1.parent)

end

@testset "macro" begin
    @test isequal(hex2bytes("2A864886F70D01010B"), ASN.@oid("1.2.840.113549.1.1.11"))
end

# TODO this should become a test for Lookup
@skip @testset "test tree refs" begin
    root = RPKI.RPKINode(nothing, [], nothing)
    lvl1 = RPKI.RPKINode(nothing, [], "Level 1")
    lvl2_1 = RPKI.RPKINode(nothing, [], "Level 2.1")
    lvl2_2 = RPKI.RPKINode(nothing, [], "Level 2.2")
    RPKI.add(lvl1, [lvl2_1, lvl2_2])
    RPKI.add(root, lvl1)
    @debug root
    @test isequal(root.children[1].obj, "Level 1")
    @test isequal(root.children[1].children[1].obj, "Level 2.1")
    @test isequal(root.children[1].children[2].obj, "Level 2.2")

    
    reftree = RPKI.RPKINode(nothing, [], "reftree root")
    RPKI.add(reftree, RPKI.RPKINode(nothing, [], lvl2_2))
    @debug reftree

    @test isequal(reftree.children[1].obj.obj, "Level 2.2")

    lvl2_2.obj = "altered 2.2"

    @test isequal(root.children[1].children[2].obj, "altered 2.2")
    @test isequal(reftree.children[1].obj.obj, "altered 2.2")

    ## now can get to 'root' from reftree?
    @test isequal(reftree.children[1].obj.parent.obj, "Level 1")

    # and change that
    reftree.children[1].obj.parent.obj = "altered Level 1"
    @test isequal(reftree.children[1].obj.parent.obj, "altered Level 1")
    @test isequal(root.children[1].obj, "altered Level 1")

    # this works!
    # conclusion: we need a prefix tree that holds RPKINodes
    # the RPKINode itself will have pointers to the parent in the original tree
    # so we can find a prefix using the prefix tree, and traverse upwards to the
    # MFT->CER and on to the root
    #
    # slightly different: we should also create a similar 'search' datastructure
    # for ASIDs taken from ROAs, perhaps Dict{Integer}{Vector{RPKINode}}
end


using BenchmarkTools
@skip @testset "lazy Content validation" begin
    file = testdata_fn("ripe-ncc-ta.cer")
    @debug "parsing $(file)"
    @time tree = DER.parse_file_recursive(file)
    @test @time isequal(ASN.lazy_contains(tree, ASN.PRINTABLESTRING, "ripe-ncc-ta"), true)

    @test isequal(length(collect(ASN.lazy_iter(tree))), length(collect(ASN.iter(tree))))
    @debug "btime for iter:"
    @btime ASN.iter(tree)
    @debug "btime for lazy_iter:"
    @btime ASN.lazy_iter(tree)
end
