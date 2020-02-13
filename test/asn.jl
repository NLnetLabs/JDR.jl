println("testing $(@__FILE__)")

using JuliASN.ASN

@skip @testset "ASN" begin
    l1  = Leaf("leaf 1")
    l2  = Leaf("leaf 2")
    root = Node(nothing, [], "root")
    seq1 = Node(root, [l1, l2], "SEQ1")
    seq2 = Node(root, [l1, l2], "SEQ2")

    ASN.append!(root, seq1)
    ASN.append!(root, seq2)
    ASN.append!(seq2, seq1)
    print_node(root, traverse=true)
    println("--")
    print_node(seq2, traverse=true)
    println("--")
    print_node(ASN.parent(seq1))
    print_node(seq1.parent)

end
