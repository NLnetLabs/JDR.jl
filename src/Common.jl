module Common
export Remark, RemarkLevel, RemarkCounts, RemarkCounts_t, count_remarks
export remark!, dbg!, info!, warn!, err!

@enum RemarkLevel DBG INFO WARN ERR

remarkTID = 0
resetRemarkTID() = global remarkTID = 0
struct Remark
    lvl::RemarkLevel
    msg::String
    tid::Int
end
Remark(lvl, msg) = Remark(lvl, msg, global remarkTID += 1)

## Example:
#struct MyObject
#    id::Integer
#    remarks::Vector{Remark}
#    remark_counts::Dict{Level, Integer}
#end
#MyObject(i::Integer) = MyObject(i, [], RemarkCounts())


# Helper for constructors:
const RemarkCounts_t = Dict{RemarkLevel, Int64}
RemarkCounts() = Dict(lvl => 0 for lvl in instances(RemarkLevel)) 

function remark!(o::Any, lvl::RemarkLevel, msg::String)
	if isnothing(o.remarks)
        o.remarks = Vector{Remark}([])
	end	
	push!(o.remarks, Remark(lvl, msg))
end

dbg!(o::Any, msg::String) 	= remark!(o, DBG, msg)
info!(o::Any, msg::String) 	= remark!(o, INFO, msg)
warn!(o::Any, msg::String) 	= remark!(o, WARN, msg)
err!(o::Any, msg::String)  	= remark!(o, ERR, msg)

function remark!(o::Any, msg::String)
    @warn "common.jl: remark!() is deprecated! defaulting to info!()" maxlog=10
    info!(o, msg)
end

function count_remarks(o::T) where {T<:Any}
    res = RemarkCounts()
    if !isnothing(o.remarks)
        for r in o.remarks
            res[r.lvl] += 1
        end
    end
    res
end

import Base.+
function +(c1::RemarkCounts_t, c2::RemarkCounts_t) :: RemarkCounts_t
    res = RemarkCounts()
    for lvl in instances(RemarkLevel)
        res[lvl] = c1[lvl] + c2[lvl]
    end
    res
end

end # module
