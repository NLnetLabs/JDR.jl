module RPKI
using ..ASN
using ..DER

#abstract type RPKIObject <: AbstractNode end
struct RPKIObject{T}
    filename::String
    tree::Node
end
struct CER end # <: RPKIObject end 
struct MFT end # <: RPKIObject end 
struct CRL end # <: RPKIObject end 
struct ROA end # <: RPKIObject end 

function RPKIObject(filename::String)::RPKIObject
    tree = DER.parse_file_recursive(filename)
    ext = lowercase(splitext(filename)[2])
    if      ext == ".cer" RPKIObject{CER}(filename, tree)
    elseif  ext == ".mft" RPKIObject{MFT}(filename, tree)
    end
end

function check(o::RPKIObject{CER}) :: RPKIObject
    @debug "check CER"
    o.tree.remarks = ["test remark", "remark2"]
    println(o)
    o
end
function check(::RPKIObject{T}) where {T}
    @warn "unknown RPKIObject type"
end

#function check(::MFT, tree::AbstractNode) :: RPKIObject
#    @debug "check MFT"
#    o
#end


#function check(filename::String) :: RPKIObject
#    tree = DER.parse_file_recursive(filename)
#    filetype = lowercase(splitext(filename)[2])
#    obj = RPKIObject(tree, filetype) 
#    @debug obj, typeof(tree)
#    check(obj)
#    #check(RPKIObject(tree, filetype))
#end

end # module
