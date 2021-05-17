using JDR.ASN1
using JDR.ASN1.ASN
using JDR.ASN1.DER
using JDR.RPKI
using JDR.RPKICommon
using JDR.Common
using TimerOutputs


# example from wikipedia
BLOB=hex2bytes(b"3013020105160e416e79626f64792074686572653f")
LONGFORM=hex2bytes(b"3f5501ff")
LONGLENGTH=vcat(hex2bytes(b"3082040A") , zeros(UInt8, 2000))


@testset "DER" begin
    b1 = DER.Buf(BLOB)
    tag =  DER.next!(b1)
    @test ASN.class(tag) ==  0x00
    @test ASN.constructed(tag) == true
    @test tag.number == Tagnumber(0x10) == ASN1.SEQUENCE
    @test tag.len ==  19

    tag2 = DER.next!(b1)
    @test tag2.number == Tagnumber(0x02) == ASN1.INTEGER
    @test tag2.len == 1
    @test ASN.value(tag2) == 5 #.value[1]), 5) #ugly

    tag3 = DER.next!(b1)
    @test tag3.number == Tagnumber(0x16) == ASN1.IA5STRING
    @test tag3.len == 14

    # long form 
    b2 = DER.Buf(LONGFORM)
    tag4 = DER.next!(b2)
    @test tag4.number == ASN1.Unimplemented

    # long length
    b3 = DER.Buf(LONGLENGTH)
    tag5 = DER.next!(b3)
    @test tag5.len == 1034
end
