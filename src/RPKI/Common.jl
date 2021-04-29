module RPKICommon


using ..JDR
using ..JDR.Common
using ..ASN1.ASN
using Dates
using IntervalTrees
using Sockets

export RPKIObject, RPKINode, TmpParseInfo, Lookup, print_ASN1
export RootCER, CER, MFT, ROA, CRL
export add_resource!
export root_to
export iterate

mutable struct RPKIObject{T}
    filename::String
    tree::Union{Nothing, Node}
    object::T
    remarks::Union{Nothing, Vector{Remark}}
    remarks_tree::Union{Nothing, Vector{Remark}}
    sig_valid::Union{Nothing, Bool}
    cms_digest_valid::Union{Nothing, Bool}
end

function add_resource!(::T, ::U, ::U) where {T,U} end
function add_resource!(t::T, u::U) where {T,U} 
    @warn "called generic add_resource!, t isa $(typeof(t)), u isa $(typeof(u))"
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
    RPKIObject{T}(filename, tree, T(), nothing, nothing, nothing, nothing)
end

# TODO:
# - can (do we need to) we further optimize/parametrize RPKINode on .obj?
# - should children and/or siblings be a Union{nothing, Vector} to reduce
# allocations?
mutable struct RPKINode
    parent::Union{Nothing, RPKINode}
    children::Vector{RPKINode}
    siblings::Union{Nothing, Vector{RPKINode}}
    obj::Union{Nothing, RPKIObject, String}
    # remark_counts_me could be a wrapper to the obj.remark_counts_me 
    remark_counts_me::Union{Nothing, RemarkCounts_t}
    remark_counts_children::Union{Nothing, RemarkCounts_t}
end

RPKINode() = RPKINode(nothing, RPKINode[], nothing, nothing, RemarkCounts(), RemarkCounts())
RPKINode(o::RPKIObject) = RPKINode(nothing, RPKINode[], nothing, o, RemarkCounts(), RemarkCounts())
RPKINode(s::String) = RPKINode(nothing, RPKINode[], nothing, s, RemarkCounts(), RemarkCounts())

import Base: iterate
Base.IteratorSize(::RPKINode) = Base.SizeUnknown()
function iterate(n::RPKINode, to_check=RPKINode[n])
    if isnothing(n) 
        return nothing
    end
    if isempty(to_check)
        return nothing
    end

    res = popfirst!(to_check)
    #
    # CER and CRLs are siblings, and can cause an infinite loop if we simply
    # always append .siblings to to_check.
    # But, CRLs are also the child of a MFT. By not appending the siblings, we
    # prevent the infinite loop, and still get all the RPKINodes without any
    # duplicates.

    Base.append!(to_check, [res.children...])
    return res, to_check
end

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

include("Lookup.jl")

mutable struct TmpParseInfo
    repodir::String
    lookup::Lookup
    setNicenames::Bool
    stripTree::Bool
    subjectKeyIdentifier::Vector{UInt8}
    signerIdentifier::Vector{UInt8}
    eContent::Union{Nothing,ASN.Node}
    signedAttrs::Union{Nothing,ASN.Node}
    saHash::String

    caCert::Union{Nothing,ASN.Node}
    issuer::Vector{String} # stack

    eeCert::Union{Nothing,ASN.Node}
    ee_rsaExponent::Union{Nothing,ASN.Node}
    ee_rsaModulus::Union{Nothing,ASN.Node}

    eeSig::Union{Nothing,ASN.Node}
    #certStack::Vector{RPKI.CER} # to replace all the other separate fields here
    certStack::Vector{Any} # TODO rearrange include/modules so we can actually use type RPKI.CER here

    # used in MFT to check file hashes
    cwd::String
    # for ROA:
    afi::UInt32
    # to verify CMS digest in MFT/ROAs:
    cms_message_digest::String
end
TmpParseInfo(;repodir=JDR.CFG["rpki"]["rsyncrepo"],lookup=Lookup(),nicenames::Bool=true,stripTree=false) = TmpParseInfo(repodir, lookup, nicenames, stripTree,
                                                    [],
                                                    [],
                                                    nothing,
                                                    nothing,
                                                    "",

                                                    nothing,
                                                    [],

                                                    nothing,
                                                    nothing,
                                                    nothing,
                                                    nothing,
                                                    [],
                                                    "",
                                                    0x0,
                                                    "")




struct RootCER
    resources_v6::IntervalTree{IPv6, IntervalValue{IPv6, Vector{RPKINode}}}
    resources_v4::IntervalTree{IPv4, IntervalValue{IPv4, Vector{RPKINode}}}
end
RootCER() = RootCER(IntervalTree{IPv6, IntervalValue{IPv6, Vector{RPKINode}}}(), IntervalTree{IPv4, IntervalValue{IPv4, Vector{RPKINode}}}())
RPKIObject{RootCER}(rootcer::RootCER=RootCER()) = RPKIObject("", nothing, rootcer, nothing, nothing, nothing, nothing)


struct ASIdentifiers
    ids::Vector{AutSysNum}
    ranges::Vector{OrdinalRange{AutSysNum}}
end

struct SerialNumber
    serial::Integer
end
Base.convert(::Type{SerialNumber}, i::Integer) = SerialNumber(i)
Base.string(s::SerialNumber) = uppercase(string(s.serial, base=16))

const LinkedResources{T<:IPAddr} = IntervalMap{T, Vector{RPKINode}}
Base.@kwdef mutable struct CER 
    serial::SerialNumber = 0
    notBefore::Union{Nothing, DateTime} = nothing
    notAfter::Union{Nothing, DateTime} = nothing
    pubpoint::String = ""
    manifest::String = ""
    rrdp_notify::String = ""
    selfsigned::Union{Nothing, Bool} = nothing
    validsig::Union{Nothing, Bool} = nothing
    rsa_modulus::BigInt = 0
    rsa_exp::Int = 0

    issuer::String = ""
    subject::String = ""

    inherit_v6_prefixes::Union{Nothing, Bool} = nothing
    inherit_v4_prefixes::Union{Nothing, Bool} = nothing
    resources_v6::LinkedResources{IPv6} = LinkedResources{IPv6}() 
    resources_v4::LinkedResources{IPv4} = LinkedResources{IPv4}() 

    inherit_ASNs::Union{Nothing, Bool} = nothing
    ASNs::AsIdsOrRanges = AsIdsOrRanges()

    resources_valid::Union{Nothing,Bool} = nothing
end

function Base.show(io::IO, cer::CER)
    print(io, "  pubpoint: ", cer.pubpoint, '\n')
    print(io, "  manifest: ", cer.manifest, '\n')
    print(io, "  rrdp: ", cer.rrdp_notify, '\n')
    print(io, "  notBefore: ", cer.notBefore, '\n')
    print(io, "  notAfter: ", cer.notAfter, '\n')
    printstyled(io, "  ASNs: \n")
    print(io, "    ", join(cer.ASNs, ","), "\n")
end



mutable struct MFT
    files::Vector{String}
    loops::Union{Nothing, Vector{String}}
    missing_files::Union{Nothing, Vector{String}}
    this_update::Union{Nothing, DateTime}
    next_update::Union{Nothing, DateTime}
end
MFT() = MFT([], nothing, nothing, nothing, nothing)


const _VRPS{T<:IPAddr} = IntervalMap{T, UInt8}
"""
    VRPS

    Holds the IPv6 and IPv4 resources listed on this ROA, as an IntervalTree,
    with Values denoting the maxlength.

"""
struct VRPS
    resources_v6::_VRPS{IPv6}
    resources_v4::_VRPS{IPv4}
end
VRPS() = VRPS(_VRPS{IPv6}(), _VRPS{IPv4}())

mutable struct ROA
    asid::Integer
    vrp_tree::VRPS
    resources_valid::Union{Nothing,Bool}
    resources_v6::Union{Nothing, IntervalTree{IPv6}}
    resources_v4::Union{Nothing, IntervalTree{IPv4}}
end
ROA() = ROA(0, VRPS(),
            nothing,
            IntervalTree{IPv6, Interval{IPv6}}(),
            IntervalTree{IPv4, Interval{IPv4}}(),
           )


mutable struct CRL 
    revoked_serials::Vector{SerialNumber} # TODO also include Revocation Date for each serial
    this_update::Union{Nothing, DateTime}
    next_update::Union{Nothing, DateTime}
end
CRL() = CRL([], nothing, nothing)
Base.show(io::IO, crl::CRL) = print(io, crl.this_update, " -> ", crl.next_update, "\n", crl.revoked_serials)

end # module
