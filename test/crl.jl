@skip @testset "RIPE NCC crl" begin
    o = RPKI.check(RPKI.RPKIObject(testdata_fn("ripe-ncc-ta.crl")))
    ASN.print_node(o.tree, traverse=true)
end
@testset "Object checks: *.crl" begin
    all_files = all_rpki_files(ROUTINATOR_DIR, ["crl"])
    @debug "got $(length(all_files)) .crl files to check"
    @time begin
    for (i, file) in enumerate(all_files)
        try
            #@debug file
            r = RPKI.RPKIObject(file)
            #@debug typeof(r)
            o = RPKI.check(r)
            #print(o.object.prefixes)
            print("\r$(i) parsed")
        catch e
            @error "error for $(file)"
            showerror(stderr, e, catch_backtrace())
            break
        end
    end
    end #time
end

