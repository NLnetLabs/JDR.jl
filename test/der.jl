println("testing $(@__FILE__)")

#using JuliASN
using JuliASN.ASN
using JuliASN.DER
using JuliASN.RPKI

# example from wikipedia
BLOB=hex2bytes(b"3013020105160e416e79626f64792074686572653f")
LONGFORM=hex2bytes(b"3f5501ff")
LONGLENGTH=vcat(hex2bytes(b"3082040A") , zeros(UInt8, 2000))


@testset "DER" begin
    b1 = DER.Buf(BLOB)
    tag =  DER.next!(b1)
    @test isequal(tag.class, 0x00)
    @test isequal(tag.constructed, true)
    @test isequal(tag.number, 0x10)
    @test isequal(tag.len, 19)

    tag2 = DER.next!(b1)
    @test isequal(tag2.number, 0x02)
    @test isequal(tag2.len, 1)
    @test isequal(Int(tag2.value[1]), 5) #ugly

    tag3 = DER.next!(b1)
    @test isequal(tag3.number, 0x16)
    @test isequal(tag3.len, 14 )

    # long form 
    b2 = DER.Buf(LONGFORM)
    tag4 = DER.next!(b2)
    @test isequal(tag4.number, 0x55)
    @test isequal(typeof(tag4), ASN.Tag{ASN.Unimplemented})


    # long length
    b3 = DER.Buf(LONGLENGTH)
    tag5 = DER.next!(b3)
    @test isequal(tag5.len, 1034)
end

@testset "RIR TAs" begin
    RIR_CERS = [
                "ripe-ncc-ta.cer",
                "arin-rpki-ta.cer",
                "rta-lacnic-rpki.cer",
                "apnic-rpki-root-iana-origin.cer",
                "AfriNIC.cer"
               ]
    for cer in RIR_CERS
        tree = DER.parse_file_recursive(testdata_fn(cer))
        #ASN.print_node(tree, traverse=true)
    end
end


@testset "RIR manifests" begin
    RIR_MFTS = [
                "ripe-ncc-ta.mft",
                "arin.mft",
                "lacnic.mft",
                "afrinic.mft"
               ]
    for mft in RIR_MFTS
        tree = DER.parse_file_recursive(testdata_fn("ripe-ncc-ta.mft"))
        #ASN.print_node(tree, traverse=true)
    end
end


@skip @testset "Full RPKI repo parse test" begin
    @debug "globbing ..."
    @time all_files = all_rpki_files(ROUTINATOR_DIR)
    @debug "got  $(length(all_files)) files to check"
    failed_files = []
    @time begin
        parsed = 0
        for file in all_files
            try
                #tree = Base.Threads.@spawn DER.parse_file_recursive(file)
                ##FIXME we need a @sync to catch the exceptions..
                tree = DER.parse_file_recursive(file)
                parsed += 1
                print("\r$(parsed) parsed")
            catch e
                @warn "exception while parsing $(file)"
                #println(e)
                #stacktrace()
                showerror(stderr, e, catch_backtrace())
                push!(failed_files, file)
                throw(e) # use this to debug
                #break
            end
        end
    end # @time
    GC.gc() # FIXME this is to clean up file descriptors when using Mmap,
            # is this a bug?
            
    @test isempty(failed_files)
    #for failed_file in failed_files
    #    cp(failed_file, joinpath(dirname(pathof(JuliASN)), "..", "test", "testdata", "failed_files", basename(failed_file)))
    #end
end


@testset "Content validation" begin
    file = testdata_fn("ripe-ncc-ta.cer")
    #@debug "parsing $(file)"
    tree = DER.parse_file_recursive(file)
    @test isequal(ASN.contains(tree, ASN.PRINTABLESTRING, "ripe-ncc-ta"), true)

    s = Set{Pair{Type{<:ASN.AbstractTag}, Any}}() 
    push!(s, ASN.OID => "2.5.4.3")
    push!(s, ASN.OID => "1.2.840.113549.1.1.11")
    push!(s, ASN.PRINTABLESTRING => "ripe-ncc-ta")
    @test isequal(ASN.contains_set(tree, s), true)
    

    v = Vector{Pair{Type{T} where {T<:ASN.AbstractTag}, Any}}() 
    push!(v, ASN.OID => "1.2.840.113549.1.1.11")
    push!(v, ASN.OID => "2.5.4.3")
    push!(v, ASN.PRINTABLESTRING => "ripe-ncc-ta")
    @test isequal(ASN.contains_in_order(tree, v), true)
end


