using Revise, Jive
using JuliASN
using Test
using Glob

ROUTINATOR_DIR = "/home/luuk/.rpki-cache/repository/rsync/"
TESTDATA = joinpath(dirname(pathof(JuliASN)), "..", "test", "testdata")


# some helpers:
testdata_fn(filename::String) = joinpath(dirname(pathof(JuliASN)), "..", "test", "testdata", filename)

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
    runtests(@__DIR__, skip=["runtests.jl"])
end

watch(trigger, @__DIR__, sources=[pathof(JuliASN)])
trigger("")

Base.JLOptions().isinteractive==0 && wait()
