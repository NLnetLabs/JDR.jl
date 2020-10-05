module RPKICommon


using ..JDR.Common
using ..ASN
using Dates

export RPKIObject, RPKINode, TmpParseInfo, Lookup, print_ASN1
export CER, MFT, ROA, CRL
export VRP

mutable struct RPKIObject{T}
    filename::String
    tree::Union{Nothing, Node}
    object::T
    remarks::Union{Nothing, Vector{Remark}}
    remarks_tree::Union{Nothing, Vector{Remark}}
end


function Base.show(io::IO, obj::RPKIObject{T}) where T
    print(io, "RPKIObject type: ", nameof(typeof(obj).parameters[1]), '\n')
    print(io, "filename: ", basename(obj.filename), '\n')
    print(io, obj.object)
end

function print_ASN1(o::RPKIObject{T}; max_lines=0) where T
    ASN.print_node(o.tree; traverse=true, max_lines)
end


function RPKIObject{T}(filename::String, tree::Node) where T 
    RPKIObject{T}(filename, tree, T(), nothing, nothing)
end

# TODO:
# - can (do we need to) we further optimize/parametrize RPKINode on .obj?
mutable struct RPKINode
    parent::Union{Nothing, RPKINode}
    children::Vector{RPKINode}
    obj::Union{Nothing, RPKIObject, String}
    # remark_counts_me could be a wrapper to the obj.remark_counts_me 
    remark_counts_me::RemarkCounts_t
    remark_counts_children::RemarkCounts_t
end
# FIXME: check how we actually use RPKINode() throughout the codebase
RPKINode(p, c, o) = RPKINode(p, c, o, RemarkCounts(), RemarkCounts())


function root_to(n::RPKINode)
    res = [n]
    cur = n
    while !(isnothing(cur.parent))
        push!(res, cur.parent)
        cur = cur.parent
    end
    reverse(res)
end

function Base.show(io::IO, node::RPKINode) 
    if !(isnothing(node.obj))
        print(io, "RPKINode [$(nameof(typeof(node.obj).parameters[1]))] $(node.obj.filename)")
    else
        print(io, "RPKINode")
    end
end

function Base.show(io::IO, m::MIME"text/html", node::RPKINode) 
    path = root_to(node) 
    print(io, "<ul>")
    for p in path[1:end-1]
        print(io, "<li>")
        if !(isnothing(p.obj))
            print(io, "RPKINode [$(nameof(typeof(p.obj).parameters[1]))] $(p.obj.filename) ")
        else
            print(io, "RPKINode")
        end
        print(io, "</li><ul>")
    end
    print(io, "<li>RPKINode [$(nameof(typeof(node.obj).parameters[1]))] <b>$(node.obj.filename)</b></li>")
    print(io, "<ul><li>$(length(node.children)) child nodes</li></ul>")
    for _ in length(path)
        print(io, "</ul>")
    end
end

include("../Lookup.jl")

mutable struct TmpParseInfo
    lookup::Lookup
    setNicenames::Bool
    stripTree::Bool
    subjectKeyIdentifier::Vector{UInt8}
    signerIdentifier::Vector{UInt8}
    eContent::Union{Nothing,ASN.Node}
    signedAttrs::Union{Nothing,ASN.Node}
    saHash::String

    caCert::Union{Nothing,ASN.Node}
    ca_rsaExponent::Vector{Integer} # stack
    ca_rsaModulus::Vector{BigInt} # stack
    issuer::Vector{String} # stack

    eeCert::Union{Nothing,ASN.Node}
    ee_rsaExponent::Union{Nothing,ASN.Node}
    ee_rsaModulus::Union{Nothing,ASN.Node}

    eeSig::Union{Nothing,ASN.Node}
    #certStack::Vector{RPKI.CER} # to replace all the other separate fields here
    certStack::Vector{Any} # TODO rearrange include/modules so we can actually use type RPKI.CER here
    certValid::Union{Nothing,Bool}

    # for ROA:
    afi::UInt32
end
TmpParseInfo(;lookup=Lookup(),nicenames::Bool=true,stripTree=false) = TmpParseInfo(lookup, nicenames, stripTree,
                                                    [],
                                                    [],
                                                    nothing,
                                                    nothing,
                                                    "",

                                                    nothing,
                                                    [],
                                                    [],
                                                    [],

                                                    nothing,
                                                    nothing,
                                                    nothing,
                                                    nothing,
                                                    [],
                                                    nothing,
                                                    0x0)




struct ASIdentifiers
    ids::Vector{AutSysNum}
    ranges::Vector{OrdinalRange{AutSysNum}}
end
mutable struct CER 
    serial::Integer
    pubpoint::String
    manifest::String
    rrdp_notify::String
    selfsigned::Union{Nothing, Bool}
    validsig::Union{Nothing, Bool}
    rsa_modulus::BigInt
    rsa_exp::Int

    issuer::String
    subject::String

    inherit_prefixes::Bool
    #prefixes::Vector{Union{IPNet, Tuple{IPNet, IPNet}}}
    prefixes::IPPrefixesOrRanges
    inherit_ASNs::Bool
    #ASNs::Vector{Union{Tuple{UInt32, UInt32}, UInt32}}
    ASNs::AsIdsOrRanges
end
CER() = CER(0, "", "", "", nothing, nothing, 0, 0, "", "",
            false, IPPrefixesOrRanges(),
            false, AsIdsOrRanges())


mutable struct MFT
    files::Vector{String}
    loops::Union{Nothing, Vector{String}}
    missing_files::Union{Nothing, Vector{String}}
    this_update::Union{Nothing, DateTime}
    next_update::Union{Nothing, DateTime}
end
MFT() = MFT([], nothing, nothing, nothing, nothing)

struct VRP{AFI<:IPNet}
    prefix::AFI
    maxlength::Integer
end

mutable struct ROA
    asid::Integer
    vrps::Vector{VRP}
    prefixes::IPPrefixesOrRanges # on the EE cert
    rsa_modulus::BigInt
    rsa_exp::Int
    local_eContent_hash::String
end
ROA() = ROA(0, [], IPPrefixesOrRanges(), 0, 0, "EMPTY_LOCAL_HASH")

end # module