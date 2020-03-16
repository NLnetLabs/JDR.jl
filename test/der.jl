println("testing $(@__FILE__)")

#using JuliASN
using JuliASN.ASN
using JuliASN.DER
using JuliASN.RPKI

using Glob

# example from wikipedia
BLOB=hex2bytes(b"3013020105160e416e79626f64792074686572653f")
LONGFORM=hex2bytes(b"3f5501")
LONGLENGTH=hex2bytes(b"3082040A")


TESTDATA = joinpath(dirname(pathof(JuliASN)), "..", "test", "testdata")

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

@skip @testset "RIR TAs" begin
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

@skip @testset "RIR manifests" begin
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
    @time tree = DER.parse_file_recursive(fn("lacnic.mft"))
    ASN.print_node(tree, traverse=true)

    @debug "AFRINIC manifest"
    @time tree = DER.parse_file_recursive(fn("afrinic.mft"))
    ASN.print_node(tree, traverse=true)

end


function all_rpki_files(dir)
    all_files = []
    for d in walkdir(dir), ext in ["cer", "mft", "crl", "roa"]
        Base.append!(all_files, glob("*.$(ext)", d[1]))
    end
    all_files
end

@skip @testset "Full RPKI repo parse test" begin
    ROUTINATOR_DIR = "/home/luuk/.rpki-cache/repository/rsync/"
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


@skip @testset "Individual file parsing" begin
    file = fn("afrinic.mft")
    #file = fn("failed_files/9VjbDK9tRIMfvuISNaHQx4TeoqU.roa")
    @debug "parsing $(file)"
    @time tree = DER.parse_file_recursive(file)
    ASN.print_node(tree, traverse=true)
end

@testset "Content validation" begin
    file = fn("ripe-ncc-ta.cer")
    @debug "parsing $(file)"
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

using BenchmarkTools
@skip @testset "lazy Content validation" begin
    file = fn("ripe-ncc-ta.cer")
    @debug "parsing $(file)"
    @time tree = DER.parse_file_recursive(file)
    @test @time isequal(ASN.lazy_contains(tree, ASN.PRINTABLESTRING, "ripe-ncc-ta"), true)

    @test isequal(length(collect(ASN.lazy_iter(tree))), length(collect(ASN.iter(tree))))
    @debug "btime for iter:"
    @btime ASN.iter(tree)
    @debug "btime for lazy_iter:"
    @btime ASN.lazy_iter(tree)
end


@testset "Object checks" begin
    file = fn("ripe-ncc-ta.cer")
    r = RPKI.RPKIObject(file)
    RPKI.check(r)
    ASN.print_node(r.tree, traverse=true)
end
