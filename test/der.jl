println("testing $(@__FILE__)")

using JuliASN.DER

# example from wikipedia
BLOB=hex2bytes(b"3013020105160e416e79626f64792074686572653f")
LONGFORM=hex2bytes(b"3f55")

@testset "DER" begin
    b1 = DER.Buf(BLOB)
    tag =  DER.next(b1)
    @test isequal(tag.class, 0x00)
    @test isequal(tag.constructed, true)
    @test isequal(tag.number, 0x10)
    @test isequal(tag.len, 19)
    DER.print_tag(tag)

    tag2 = DER.next(b1)
    @test isequal(tag2.number, 0x02)
    @test isequal(tag2.len, 1)
    @test isequal(Int(tag2.value[1]), 5) #ugly
    DER.print_tag(tag2)

    tag3 = DER.next(b1)
    @test isequal(tag3.number, 0x16)
    @test isequal(tag3.len, 14 )
    DER.print_tag(tag3)

    # long form error
    b2 = DER.Buf(LONGFORM)
    @test_throws DER.NotImplementedYetError DER.next(b2)
end

@skip @testset "RPKI cert" begin
    fn = joinpath(dirname(pathof(JuliASN)), "..", "test", "ripe-ncc-ta.cer")
    buf = DER.Buf(open(fn))
    println("parsing  file")
    while !isnothing(DER.next(buf))
        print('.')
    end
    println("done!")
end


@testset "Buf" begin
    buf = DER.Buf(hex2bytes("0011223344"))
    #@test isequal(buf.index, 1)
end
