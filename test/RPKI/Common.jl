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

