using IPNets
@testset "PrefixTree v4 tests" begin
    tree = PrefixTree{String}()
    tree[IPv4Net("103.249.152.0/24") ] = "foo"
    tree[IPv4Net("195.234.56.0/24") ] = "bar"
    @test length(values(tree)) == 2
    @test length(values(subtree(tree, IPv4Net("1.0.0.0/24")))) == 0

    tree = PrefixTree{String}()
    tree[IPv4Net("2.56.16.0/22") ] = "NL"
    tree[IPv4Net("2.56.20.0/22") ] = "CZ"
    @test length(values(subtree(tree, IPv4Net("2.56.0.0/16")))) == 2
    @test values(firstparent(tree, IPv4Net("2.56.16.0/24"))) == ["NL"]
    @test isempty(values(firstparent(tree, IPv4Net("1.0.0.0/8"))))

end
