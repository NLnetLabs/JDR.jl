using Revise, Jive
using JuliASN
using Test

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
