println("testing $(@__FILE__)")

#using JuliASN
using JuliASN.ASN
using JuliASN.DER

# example from wikipedia
BLOB=hex2bytes(b"3013020105160e416e79626f64792074686572653f")
LONGFORM=hex2bytes(b"3f5501")
LONGLENGTH=hex2bytes(b"3082040A")

@skip @testset "DER" begin
    b1 = DER.Buf(BLOB)
    tag =  DER.next(b1)
    @test isequal(tag.class, 0x00)
    @test isequal(tag.constructed, true)
    @test isequal(tag.number, 0x10)
    @test isequal(tag.len, 19)
    #DER.print_tag(tag)

    tag2 = DER.next(b1)
    @test isequal(tag2.number, 0x02)
    @test isequal(tag2.len, 1)
    @test isequal(Int(tag2.value[1]), 5) #ugly
    #DER.print_tag(tag2)

    tag3 = DER.next(b1)
    @test isequal(tag3.number, 0x16)
    @test isequal(tag3.len, 14 )
    #DER.print_tag(tag3)

    # long form error
    b2 = DER.Buf(LONGFORM)
    tag4 = DER.next(b2)
    @test isequal(tag4.number, 0x55)


    # long length
    b3 = DER.Buf(LONGLENGTH)
    tag5 = DER.next(b3)
    @test isequal(tag5.len, 1034)
end

fn(filename::String) = joinpath(dirname(pathof(JuliASN)), "..", "test", "testdata", filename)

@testset "RIR TAs" begin
    @debug "RIPE NCC"
    tree = DER.parse_file_recursive(fn("ripe-ncc-ta.cer"))
    ASN.print_node(tree, traverse=true)
    
    @debug "ARIN"
    tree = DER.parse_file_recursive(fn("arin-rpki-ta.cer"))
    ASN.print_node(tree, traverse=true)
    @debug "LACNIC"
    tree = DER.parse_file_recursive(fn("rta-lacnic-rpki.cer"))
    ASN.print_node(tree, traverse=true)
    @debug "APNIC"
    tree = DER.parse_file_recursive(fn("apnic-rpki-root-iana-origin.cer"))
    ASN.print_node(tree, traverse=true)
    @debug "AFRINIC"
    tree = DER.parse_file_recursive(fn("AfriNIC.cer"))
    ASN.print_node(tree, traverse=true)
end

@testset "others" begin
    @debug "RIPE NCC manifest"
    @time tree = DER.parse_file_recursive(fn("ripe-ncc-ta.mft"))
    ASN.print_node(tree, traverse=true)

    @debug "ARIN manifest"
    @time tree = DER.parse_file_recursive(fn("arin.mft"))
    ASN.print_node(tree, traverse=true)

    @debug "LACNIC manifest"
    @time tree = DER.parse_file_recursive(fn("lacnic.mft"))
    ASN.print_node(tree, traverse=true)

    @debug "APNIC manifest"
    @time tree = DER.parse_file_recursive(fn("apnic.mft"))
    ASN.print_node(tree, traverse=true)

    @debug "AFRINIC manifest"
    @time tree = DER.parse_file_recursive(fn("afrinic.mft"))
    ASN.print_node(tree, traverse=true)
end
