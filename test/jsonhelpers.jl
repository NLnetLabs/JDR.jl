using JDR.JSONHelpers
using JSON2


@testset "Vue tree" begin
    TAL_URLS = Dict(
        :afrinic    => "rsync://rpki.afrinic.net/repository/AfriNIC.cer",
        :ripe       => "rsync://rpki.ripe.net/ta/ripe-ncc-ta.cer",
    )
    (tree, lookup) = RPKI.retrieve_all();
    res = RPKI.lookup(lookup, RPKI.AutSysNum(136525))

    # AS 136525 has uneven branches, occurs RIPE/AfriNIC/APNIC/LACNIC

    #b1 = to_vue_branch(res[1])
    #b2 = to_vue_branch(res[2])

    #t = to_vue_tree([b1, b2])
    t = to_vue_tree(map(to_vue_branch, res))
    open("/tmp/test.json", "w") do fn
        JSON2.write(fn, t)
    end

end

@skip @testset "Find uneven branches" begin
    (tree, lookup) = RPKI.retrieve_all();
    #res = RPKI.lookup(lookup, RPKI.AutSysNum(33764))
    for a in lookup.ASNs
        branches = [to_vue_branch(b) for b in a.second]
        lens = [length(b) for b in branches]
        if length(unique(lens)) > 1
            @debug a.first, lens
            break
        end
    end
    1
end
