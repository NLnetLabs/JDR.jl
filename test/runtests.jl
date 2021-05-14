using JDR
using Jive, Test

ROUTINATOR_DIR = "/home/luuk/.rpki-cache/repository/rsync/"
TESTDATA = joinpath(dirname(pathof(JDR)), "..", "test", "testdata")


# some helpers:
testdata_fn(filename::String) = joinpath(dirname(pathof(JDR)), "..", "test", "testdata", filename)


runtests(@__DIR__, skip=["revise.jl"])
