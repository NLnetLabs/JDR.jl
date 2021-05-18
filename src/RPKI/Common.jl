module RPKICommon


using JDR.Config: CFG
using JDR.Common: Remark, RemarkCounts_t, AutSysNum, AsIdsOrRanges, IPRange, split_scheme_uri
using JDR.ASN1: Node, print_node
using JDR.ASN1.DER: parse_file_recursive

using Dates: DateTime, TimePeriod, Hour, now, UTC
using IntervalTrees
using Sockets

# for Lookup.jl:
using StatsBase
using Query

export RPKIObject, RPKINode, TmpParseInfo, Lookup, RPKIFile, RootCER, CER, MFT, ROA, CRL, vrps, vrps_v4, vrps_v6
export add_resource!, get_object, root_to, iterate, print_ASN1

# from Lookup.jl:
export search, new_since, add_filename!, add_missing_filename!, add_resource, get_pubpoint

abstract type RPKIFile end

"""
    RPKIObject{T<:RPKIFile}

Contains an `object` T (i.e. a `CER`, `MFT`, `CRL` or `ROA`), decoded from `filename` into an
annotated ASN1 tree in `tree`. Any warnings or errors for this object are stored in `remarks`.
"""
mutable struct RPKIObject{T<:RPKIFile}
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
    print_node(o.tree; traverse=true, max_lines)
end


function RPKIObject{T}(filename::String, tree::Node) where {T<:RPKIFile}
    RPKIObject{T}(filename, tree, T(), nothing, nothing, nothing, nothing)
end

# TODO:
# - can (do we need to) we further optimize/parametrize RPKINode on .obj?
# - should children and/or siblings be a Union{nothing, Vector} to reduce
# allocations?

"""
    RPKINode

Represents a file in the RPKI, with pointers to its `parent`, `children` and possible `siblings`.

The `obj` points to the `RPKIObject{T}` of this RPKINode, e.g. a `RPKIObject{CER}`.
"""
mutable struct RPKINode
    parent::Union{Nothing, RPKINode}
    children::Vector{RPKINode}
    siblings::Union{Nothing, Vector{RPKINode}}
    obj::Union{Nothing, RPKIObject, String}
    # remark_counts_me could be a wrapper to the obj.remark_counts_me 
    remark_counts_me::Union{Nothing, RemarkCounts_t}
    remark_counts_children::Union{Nothing, RemarkCounts_t}
end

RPKINode() = RPKINode(nothing, RPKINode[], nothing, nothing, nothing, nothing)
RPKINode(o::RPKIObject) = RPKINode(nothing, RPKINode[], nothing, o, nothing, nothing)
#RPKINode() = RPKINode(nothing, RPKINode[], nothing, nothing, RemarkCounts(), RemarkCounts())
#RPKINode(o::RPKIObject) = RPKINode(nothing, RPKINode[], nothing, o, RemarkCounts(), RemarkCounts())
##RPKINode(s::String) = RPKINode(nothing, RPKINode[], nothing, s, RemarkCounts(), RemarkCounts()) # DEPR

get_object(n::RPKINode) = n.obj.object
get_object(o::RPKIObject) = o.object

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

function Base.show(io::IO, ::MIME"text/html", node::RPKINode) 
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
    for _ in 1:length(path)
        print(io, "</ul>")
    end
end

include("Lookup.jl")

"""
    remarks_above(node::RPKINode)

Find nodes between root and `node` carrying Remarks.

The result does not include `node` itself.
Note that because of the RPKINode tree structure, a path upwards from `node` to
root will consist of only manifests and certificates.

TODO: should we check siblings (i.e. CRLs) ?

"""
function remarks_above(node::RPKINode) :: Vector{RPKINode}
    root_to(node)[1:end-1] |> @filter(!isnothing(_.obj.remarks)) |> collect
end


"""
    remarks_below(node::RPKINode)

Find descendants from `node` carrying Remarks.

The result does not include `node` itself.

"""
function remarks_below(node::RPKINode) :: Vector{RPKINode}
    node.children |>
        @map(collect(_)) |>
        Iterators.flatten |>
        @filter(!isnothing(_.obj.remarks)) |>
    collect
end


mutable struct TmpParseInfo
    repodir::String
    lookup::Lookup
    setNicenames::Bool
    stripTree::Bool
    subjectKeyIdentifier::Vector{UInt8}
    signerIdentifier::Vector{UInt8}
    eContent::Union{Nothing,Node}
    signedAttrs::Union{Nothing,Node}
    saHash::String

    caCert::Union{Nothing,Node}
    issuer::Vector{String} # stack

    eeCert::Union{Nothing,Node}
    ee_rsaExponent::Union{Nothing,Node}
    ee_rsaModulus::Union{Nothing,Node}

    eeSig::Union{Nothing,Node}
    #certStack::Vector{RPKI.CER} # to replace all the other separate fields here
    certStack::Vector{Any} # TODO rearrange include/modules so we can actually use type RPKI.CER here

    # used in MFT to check file hashes
    cwd::String
    # for ROA:
    afi::UInt32
    # to verify CMS digest in MFT/ROAs:
    cms_message_digest::String
end
TmpParseInfo(;repodir=CFG["rpki"]["rsyncrepo"],lookup=Lookup(),nicenames::Bool=true,stripTree=false) = TmpParseInfo(repodir, lookup, nicenames, stripTree,
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




struct RootCER <: RPKIFile
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
Base.@kwdef mutable struct CER <: RPKIFile
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



mutable struct MFT <: RPKIFile
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

mutable struct ROA <: RPKIFile
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

struct VRP{T<:IPAddr}
    ipr::IPRange{T}
    maxlen::Union{Nothing, Int}
end

function vrps_v4(r::ROA)
    [VRP{IPv4}(IPRange(e.first, e.last), e.value) for e in r.vrp_tree.resources_v4]
end
function vrps_v6(r::ROA)
    [VRP{IPv6}(IPRange(e.first, e.last), e.value) for e in r.vrp_tree.resources_v6]
end
function vrps(r::ROA)
    vcat(vrps_v6(r), vrps_v4(r))
end

function Base.show(io::IO, vrp::VRP)
    print(io, IPRange(vrp.ipr.first, vrp.ipr.last), "-", vrp.maxlen)
end


mutable struct CRL <: RPKIFile
    revoked_serials::Vector{SerialNumber} # TODO also include Revocation Date for each serial
    this_update::Union{Nothing, DateTime}
    next_update::Union{Nothing, DateTime}
end
CRL() = CRL([], nothing, nothing)
Base.show(io::IO, crl::CRL) = print(io, crl.this_update, " -> ", crl.next_update, "\n", crl.revoked_serials)




function RPKIObject(filename::String)::RPKIObject
    tree = parse_file_recursive(filename)
    ext = lowercase(filename[end-3:end])
    if      ext == ".cer" RPKIObject{CER}(filename, tree)
    elseif  ext == ".mft" RPKIObject{MFT}(filename, tree)
    elseif  ext == ".roa" RPKIObject{ROA}(filename, tree)
    elseif  ext == ".crl" RPKIObject{CRL}(filename, tree)
    end
end
function RPKIObject{T}(filename::String)::RPKIObject{T} where {T}
    tree = parse_file_recursive(filename)
    RPKIObject{T}(filename, tree)
end

end # module
