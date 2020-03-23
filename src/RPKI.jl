module RPKI
using ..ASN
using ..DER
using IPNets

#abstract type RPKIObject <: AbstractNode end
struct RPKIObject{T}
    filename::String
    tree::Node
    object::T
end


function RPKIObject{T}(filename::String, tree::Node) where T 
    RPKIObject{T}(filename, tree, T())
end

include("RPKI/CER.jl")
include("RPKI/MFT.jl")
include("RPKI/ROA.jl")
include("RPKI/CRL.jl")

include("RPKI/validation_common.jl")


function RPKIObject(filename::String)::RPKIObject
    tree = DER.parse_file_recursive(filename)
    ext = lowercase(splitext(filename)[2])
    if      ext == ".cer" RPKIObject{CER}(filename, tree)
    elseif  ext == ".mft" RPKIObject{MFT}(filename, tree)
    elseif  ext == ".roa" RPKIObject{ROA}(filename, tree)
    end
end


function check(::RPKIObject{T}) where {T}
    @warn "unknown RPKIObject type"
end

end # module
