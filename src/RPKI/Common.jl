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


include("TAL.jl")
using .Tal: TAL, parse_tal
export parse_tal


""" Abstract type to parameterize [`RPKIObject`](@ref)
```julia-repl
julia> subtypes(RPKIFile)
5-element Vector{Any}:
 CER
 CRL
 MFT
 ROA
 RootCER
```
"""
abstract type RPKIFile end

"""
    RPKIObject{T<:RPKIFile}

Contains an `object` T (i.e. a `CER`, `MFT`, `CRL` or `ROA`), decoded from `filename` into an
annotated ASN1 tree in `tree`. Any warnings or errors for this object are stored in `remarks`.

Fields:
 - `filename::String`
 - `tree::Union{Nothing, Node}` -- ASN1.Node
 - `object::T`
 - `remarks::Union{Nothing, Vector{Remark}}`
 - `remarks_tree::Union{Nothing, Vector{Remark}}`
 - `sig_valid::Union{Nothing, Bool}`
 - `cms_digest_valid::Union{Nothing, Bool}`
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

Fields:
 - `parent::Union{Nothing, RPKINode}`
 - `children::Vector{RPKINode}`
 - `siblings::Union{Nothing, Vector{RPKINode}}`
 - `obj::Union{Nothing, RPKIObject}`
 - `remark_counts_me::Union{Nothing, RemarkCounts_t}`
 - `remark_counts_children::Union{Nothing, RemarkCounts_t}`

"""
mutable struct RPKINode
    parent::Union{Nothing, RPKINode}
    children::Union{Nothing, Vector{RPKINode}}
    siblings::Union{Nothing, Vector{RPKINode}} # TODO can only be 1, lose the vector
    obj::Union{Nothing, RPKIObject}
    # remark_counts_me could be a wrapper to the obj.remark_counts_me 
    remark_counts_me::Union{Nothing, RemarkCounts_t}
    remark_counts_children::Union{Nothing, RemarkCounts_t}
end

RPKINode() = RPKINode(nothing, nothing, nothing, nothing, nothing, nothing)
RPKINode(o::RPKIObject) = RPKINode(nothing, nothing, nothing, o, nothing, nothing)

"""
    get_object(n::RPKINode)
    get_object(o::RPKIObject)
    
Returns the wrapped object (CER, MFT, CRL, ROA) for an RPKINode or RPKIObject.
"""
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

    if !isnothing(res.children)
        Base.append!(to_check, [res.children...])
    end
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

@enum Transport rsync rrdp
export rsync, rrdp

"""
Struct to be passed around during a full run (`process_tas` or `process_ta`), containing
transient info.

Fields in this struct are mostly used 'internally' and should not be altered by hand.
Only the following fields allow for some configuration:

 - `repodir::String`, defaults to CFG["rpki"]["rsyncrepo"]
 - `nicenames::Bool`, add fieldnames and human-readable values to ASN1 trees, default `true`
 - `stripTree::Bool`, remove the ASN.1 tree to reduce memory footprint, default `false`
 - `lookup::Lookup` , to continue using an existing Lookup struct, default is an empty
   `Lookup()`. Passing an existing Lookup should be quite rare though.
"""
Base.@kwdef mutable struct TmpParseInfo
    transport::Transport = rsync::Transport
    fetch_data::Bool = false
    data_dir::String = if transport == rsync
        CFG["rpki"]["rsync_data_dir"]
    elseif transport == rrdp
        CFG["rpki"]["rrdp_data_dir"]
    else
    end

    tal::Union{Nothing, TAL} = nothing
    lookup::Lookup = Lookup()
    nicenames::Bool = true
    stripTree::Bool = false
    oneshot::Bool = false

    eContent::Union{Nothing,Node} = nothing
    signedAttrs::Union{Nothing,Node} = nothing 
    saHash::String = ""

    caCert::Union{Nothing,Node} = nothing

    eeCert::Union{Nothing,Node} = nothing
    ee_rsaExponent::Union{Nothing,Node} = nothing
    ee_rsaModulus::Union{Nothing,Node} = nothing
    ee_aki::Vector{UInt8} = []
    ee_ski::Vector{UInt8} = []

    eeSig::Union{Nothing,Node} = nothing
    certStack::Vector{RPKIFile} = []  # TODO should only be CERs, really

    # used in MFT to check file hashes
    cwd::String = ""
    # for ROA:
    afi::UInt32 = 0x0
    # to verify CMS digest in MFT/ROAs:
    cms_message_digest::String = ""
end

"""
	RootCER <: RPKIFile

Synthetic, 'empty certificate' to act as the single entry point to the RPKINode graph, with
all the RIR trust anchor certificates being its children.
"""
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

""" Simple wrapper for `serial::Integer` """
struct SerialNumber
    serial::Integer
end
Base.convert(::Type{SerialNumber}, i::Integer) = SerialNumber(i)
Base.string(s::SerialNumber) = uppercase(string(s.serial, base=16))

const LinkedResources{T<:IPAddr} = IntervalMap{T, Vector{RPKINode}}
"""
	CER <: RPKIFile

Represents a decoded certificate (.cer) file.

Fields:

Extracted from decoded file:
 - `serial`  -- Serial number on this certificate
 - `notBefore`/`notAfter` -- DateTime fields
 - `pubpoint` -- String
 - `manifest` -- String
 - `rrdp_notify` -- String
 - `selfsigned` -- Bool or Nothing
 - `issuer` -- String
 - `subject` -- String

Set after validation: 
 - `validsig` -- Bool or Nothing
 - `resources_valid` -- Bool or Nothing

"""
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

    aki::Vector{UInt8} = []
    ski::Vector{UInt8} = []

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


"""
	MFT <: RPKIFile

Represents a decoded manifest (.mft) file.

Fields:

Extracted from decoded file:
 - `files` -- `Vector{String}` containing filenames listed on this manifest
 - `loops` -- `Vector{String}` or `Nothing` listing the filenames causing a loop
 - `missing_files` -- `Vector{String}` of filenames listed in the manifest but not found on disk
 - `this_update`: `DateTime`
 - `next_update`: `DateTime`
"""
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
Holds the IPv6 and IPv4 resources listed on this ROA, as an IntervalTree,
with Values denoting the maxlength.


Fields:

 - `resources_v6::_VRPS{IPv6}`
 - `resources_v4::_VRPS{IPv4}`

These field are named this way so we can easily to coverage checks between different
RPKIObject types.  `_VRPS` is an alias for `IntervalMap{T, UInt8}`. 

"""
struct VRPS
    resources_v6::_VRPS{IPv6}
    resources_v4::_VRPS{IPv4}
end
VRPS() = VRPS(_VRPS{IPv6}(), _VRPS{IPv4}())

"""
	ROA <: RPKIFile

Represents a decoded Route Origin Authorization (.roa) file.

Fields:

 - `asid` -- Integer
 - `vrp_tree` -- [`VRPS`](@ref)
 - `resources_v6` -- `IntervalTree{IPv6}` of the IPv6 resources in the EE certificate
 - `resources_v4` -- `IntervalTree{IPv4}` of the IPv4 resources in the EE certificate

After validation:
 - `resources_valid` -- Bool or Nothing
"""
mutable struct ROA <: RPKIFile
    asid::Integer #TODO use Common.AutSysNum
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
"""
    vrps(r::ROA)
    vrps_v6(r::ROA)
    vrps_v4(r::ROA)

Get the VRPs listed on a ROA in a `Vector{VRP}`
"""
function vrps(r::ROA)
    vcat(vrps_v6(r), vrps_v4(r))
end

function Base.show(io::IO, vrp::VRP)
    print(io, IPRange(vrp.ipr.first, vrp.ipr.last), "-", vrp.maxlen)
end

"""
	CRL <: RPKIFile

Represents a decoded Certificate Revocation List (.crl) file.

Fields:

 - `revoked_serials` -- Vector of [`SerialNumber`](@ref)'s
 - `this_update` -- `DateTime`
 - `next_update` -- `DateTime`

"""
mutable struct CRL <: RPKIFile
    revoked_serials::Vector{SerialNumber} # TODO also include Revocation Date for each serial
    this_update::Union{Nothing, DateTime}
    next_update::Union{Nothing, DateTime}
end
CRL() = CRL([], nothing, nothing)
Base.show(io::IO, crl::CRL) = print(io, crl.this_update, " -> ", crl.next_update, "\n", crl.revoked_serials)



"""
    RPKIObject(filename::String)::RPKIObject{T}

Parse and return a parameterized RPKIObject, going by the extension of the passed `filename`.
"""
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

"""
    print_ASN1(n::RPKINode; max_lines=0)
    print_ASN1(o::RPKIObject{T}; max_lines=0)

Print the annotated ASN.1 tree structure for 
"""
function print_ASN1(n::RPKINode; max_lines=0) where T
    if isnothing(n.obj) || isnothing(n.obj.tree)
        @warn "no ASN.1 tree for this RPKINode, consider (re)running RPKI.check_ASN1"
    else
        print_node(n.obj.tree; traverse=true, max_lines)
    end
end
function print_ASN1(o::RPKIObject{T}; max_lines=0) where T
    if isnothing(o.tree)
        @warn "no ASN.1 tree for this RPKIObject, consider (re)running RPKI.check_ASN1"
    else
        print_node(o.tree; traverse=true, max_lines)
    end
end


end # module
