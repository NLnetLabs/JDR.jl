using Revise, Jive
using JDR
using Test
using Glob

ROUTINATOR_DIR = "/home/luuk/.rpki-cache/repository/rsync/"
TESTDATA = joinpath(dirname(pathof(JDR)), "..", "test", "testdata")


# some helpers:
testdata_fn(filename::String) = joinpath(dirname(pathof(JDR)), "..", "test", "testdata", filename)

function all_rpki_files(dir, exts=["cer", "mft", "crl", "roa"])
    all_files = []
    for d in walkdir(dir), ext in exts
        Base.append!(all_files, glob("*.$(ext)", d[1]))
    end
    all_files
end


trigger = function (path)
    printstyled("changed ", color=:cyan)
    println(path)
    sleep(0.1)
    revise()
    runtests(@__DIR__, skip=["revise.jl"])
end

watch(trigger, @__DIR__, sources=[pathof(JDR)])
trigger("")

Base.JLOptions().isinteractive==0 && wait()
