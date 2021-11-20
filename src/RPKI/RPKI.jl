module RPKI
using TimerOutputs
using JDR: CFG
using JDR.Common: RPKIUri, NotifyUri, RsyncUri
using JDR.Common: Remark, RemarkCounts_t, split_scheme_uri, count_remarks, AutSysNum, IPRange
using JDR.Common: remark_genericError!, remark_missingFile!, remark_loopIssue!, remark_manifestIssue!, remark_validityIssue!
#using JDR.RPKICommon: add_resource!, RPKIObject, RPKINode, Lookup, TmpParseInfo, add_filename!
#using JDR.RPKICommon: CER, add_resource, MFT, CRL, ROA, add_missing_filename!, RootCER, get_pubpoint
#using JDR.RPKICommon: get_object, rsync, rrdp, parse_tal
using JDR.ASN1: Node, SEQUENCE, check_tag

#using IntervalTrees: IntervalValue, IntervalMap
using Sockets: IPAddr

export process_tas, process_ta, process_cer, link_resources!
export RPKIFile, RPKIObject, RootCER, CER, MFT, CRL, ROA


##############################
# start of refactor
##############################

using Dates: DateTime, now
using IntervalTrees: IntervalTree, IntervalMap, Interval, IntervalValue
using Sockets: IPv6, IPv4
using SHA: sha256
using StaticArrays: SVector

using JDR.ASN1: Node, to_bigint
using JDR.ASN1.DER: parse_file_recursive
using JDR.Common: AsIdsOrRanges, covered, check_coverage
using JDR.Common: remark_resourceIssue!
include("TAL.jl")
using .Tal: TAL, parse_tal
export parse_tal, search

export get_pubpoint

@enum Transport rsync rrdp
export rsync, rrdp

abstract type RPKIObject end


" RPKIFile represents the Node+Object "
mutable struct RPKIFile{T<:RPKIObject}
	" The parent RPKIFile, is only `nothing` for the root RPKIFile "
	parent::Union{Nothing, RPKIFile}
    " Descendant RPKIFile(s) "
    children::Union{Nothing, RPKIFile, Vector{RPKIFile}}
	" The actual object, e.g. a CER/CRL/MFT/ROA etc. "
	object::T
	" Filename for the object "
	filename::AbstractString #TODO check, is AbstractString bad here?
    " ASN1 tree"
    asn1_tree::Union{Nothing, Node}
    " Remarks "
    remarks::Union{Nothing, Vector{Remark}}
	#siblings?
	#remarks? or on object
	#remarks_ASN1 (was remarks_tree)
	#sig_valid? cms_digest_valid? or keep that in remarks
end

Base.show(io::IO, rf::RPKIFile{T}) where {T<:RPKIObject} = print(io, "[", nameof(T), "] ", rf.filename)

Base.IteratorSize(::RPKIFile) = Base.SizeUnknown()
Base.IteratorEltype(::RPKIFile) = Base.HasEltype()
eltype(::RPKIFile) = Type{RPKIFile}
function Base.iterate(rf::RPKIFile, queue=RPKIFile[rf])
    if isempty(queue)
        return nothing
    end
    res = popfirst!(queue)
    if !isnothing(res.children)
        if res.children isa Vector
            append!(queue, res.children)
        else
            push!(queue, res.children)
        end
    end
    return res, queue
end

struct Lookup
    filenames::Dict{AbstractString}{RPKIFile}
    asns::Dict{AutSysNum}{Vector{RPKIFile}}
    vrps_v6::IntervalMap{IPv6, RPKIFile}
    vrps_v4::IntervalMap{IPv4, RPKIFile}
    remarks::Vector{Tuple{Remark, RPKIFile}}

    " Hostname pointing to one or more 'entry' points in the tree. "
    pubpoints::Dict{AbstractString}{Vector{RPKIFile}}

    #notify_urls::Dict{AbstractString}{Vector{RPKIFile}}

    #resources_v6 # done in vrps_?
    #resources_v4 # done in vrps_?
    
    #pubpoints
    #rrdp_updates # this should go elsewhere perhaps
    
    # ---
    
    #rsync_modules # was temporary
    #too_specific # guess this can be replaced by Remarks
    #invalid_* # same
    #missing_files # same?
end
function Lookup(rf::RPKIFile{<:RPKIObject}) :: Lookup
    filenames = Dict{AbstractString}{RPKIFile}()
    asns = Dict{AutSysNum}{Vector{RPKIFile}}()
    vrps_v6 = IntervalMap{IPv6, RPKIFile}()
    vrps_v4 = IntervalMap{IPv4, RPKIFile}()
    remarks = Tuple{Remark, RPKIFile}[]

    pubpoints = Dict{AbstractString}{Vector{RPKIFile}}()

    for f in rf
        filenames[f.filename] = f
        if f.object isa ROA
            asid = f.object.asid
            if asid in keys(asns)
                push!(asns[asid], f)
            else
                asns[asid] = [f]
            end
            for v in f.object.vrp_tree.resources_v6
                push!(vrps_v6, IntervalValue{IPv6, RPKIFile}(v.first, v.last, f))
            end
            for v in f.object.vrp_tree.resources_v4
                push!(vrps_v4, IntervalValue{IPv4, RPKIFile}(v.first, v.last, f))
            end
        end
        if !isnothing(f.remarks)
            for r in f.remarks
                push!(remarks, (r, f))
            end
        end
    end

    # alternative attempt to now recurse via the tree structure itself
    # instead of iterate(). This way the 'order' is maintained.
    function _sub_points(rf::RPKIFile, pubpoints::Dict)
        this_pp = get_pubpoint(rf; rsync=true)
        last_pp = if !isnothing(rf.parent)
            get_pubpoint(rf.parent; rsync=true)
        else
            "root"
        end
        if this_pp != last_pp
            if haskey(pubpoints, this_pp)
                push!(pubpoints[this_pp], rf)
            else
                pubpoints[this_pp] = [rf]
            end
        end
        if !isnothing(rf.children)
            if rf.children isa Vector
                foreach(c -> _sub_points(c, pubpoints), rf.children)
            elseif rf.children isa RPKIFile
                _sub_points(rf.children, pubpoints)
            end
        end
    end
    _sub_points(rf, pubpoints)
    
    Lookup(filenames, asns, vrps_v6, vrps_v4, remarks, pubpoints)
end
function Base.show(io::IO, lookup::Lookup)
    print(io, "filenames: ", length(lookup.filenames))
    print(io, "\n")
    print(io, "ASNs: ", length(lookup.asns))
    print(io, "\n")
    print(io, "VRPs v6/v4: ", length(lookup.vrps_v6), " / ", length(lookup.vrps_v4))
end
"""
    search(l::Lookup, filename::AbstractString) 
Search for RPKINode's related to `filename`
"""
function search(l::Lookup, filename::AbstractString) :: Dict{String}{RPKIFile}
    filter(fn->occursin(filename, first(fn)), l.filenames)
end
"""
    search(l::Lookup, asn::AutSysNum)
Search for RPKINode's related to a [`AutSysNum`](@ref)
"""
function search(l::Lookup, asn::AutSysNum) :: Vector{RPKIFile}
    get(l.asns, asn, RPKIFile[])
end

struct RootCER <: RPKIObject
    resources_v6::IntervalTree{IPv6, IntervalValue{IPv6, Vector{RPKIFile}}}
    resources_v4::IntervalTree{IPv4, IntervalValue{IPv4, Vector{RPKIFile}}}
end
RootCER() = RootCER(IntervalTree{IPv6, IntervalValue{IPv6, Vector{RPKIFile}}}(), IntervalTree{IPv4, IntervalValue{IPv4, Vector{RPKIFile}}}())

RPKIFile() = RPKIFile(nothing, RPKIFile[], RootCER(), "", nothing, nothing)
RPKIFile(parent, children, obj::T, fn::String, asn1::Node) where {T<:RPKIObject} = RPKIFile(parent, children, obj, fn, asn1, nothing)


""" Simple wrapper for `serial::Integer` """
struct SerialNumber
    serial::Integer
end
Base.convert(::Type{SerialNumber}, i::Integer) = SerialNumber(i)
Base.string(s::SerialNumber) = uppercase(string(s.serial, base=16))

struct ASIdentifiers
    ids::Vector{AutSysNum}
    ranges::Vector{OrdinalRange{AutSysNum}}
end
const LinkedResources{T<:IPAddr} = IntervalMap{T, Vector{RPKIFile}}


"""
	CER <: RPKIObject

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
Base.@kwdef mutable struct CER <: RPKIObject
    serial::SerialNumber = 0
    notBefore::Union{Nothing, DateTime} = nothing
    notAfter::Union{Nothing, DateTime} = nothing
    pubpoint::Union{Nothing, RsyncUri} = nothing
    manifest::Union{Nothing, String} = nothing
    rrdp_notify::Union{Nothing, NotifyUri} = nothing
    selfsigned::Union{Nothing, Bool} = nothing
    validsig::Union{Nothing, Bool} = nothing
    rsa_modulus::BigInt = 0
    rsa_exp::Int = 0

    issuer::Union{Nothing, String} = nothing
    subject::Union{Nothing, String} = nothing

    aki::Vector{UInt8} = UInt8[]
    ski::Vector{UInt8} = UInt8[]

    inherit_v6_prefixes::Union{Nothing, Bool} = nothing
    inherit_v4_prefixes::Union{Nothing, Bool} = nothing
    resources_v6::LinkedResources{IPv6} = LinkedResources{IPv6}() 
    resources_v4::LinkedResources{IPv4} = LinkedResources{IPv4}() 

    inherit_ASNs::Union{Nothing, Bool} = nothing
    ASNs::AsIdsOrRanges = AsIdsOrRanges()

    resources_valid::Union{Nothing,Bool} = nothing
end

add_resource!(cer::CER, ipr::IPRange{IPv6}) = push!(cer.resources_v6, IntervalValue(ipr, RPKIFile[])) #TODO: should we remove this RPKIFile[] alloc?
add_resource!(cer::CER, ipr::IPRange{IPv4}) = push!(cer.resources_v4, IntervalValue(ipr, RPKIFile[]))

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
    get_pubpoint(node::RPKINode) :: String

Get the domain name of the publication point for the file represented by this `RPKINode`.
"""
#TODO: make this use .rrdp_notify instead of .pubpoint, if available
#or, make .pubpoint to prefer rpkinotify over the rsync uri?
function get_pubpoint(rf::RPKIFile; kw...) :: AbstractString
    #@debug "get_pubpoint for $(rf)"
    if rf.object isa RootCER
        return "root"
    end
    return if rf.object isa MFT 
        @assert rf.parent.object isa CER
        get_pubpoint(rf.parent; kw...)
    else #if rf.object isa ROA || rf.object isa CRL
        @assert rf.parent.object isa MFT
        @assert rf.parent.parent.object isa CER
        get_pubpoint(rf.parent.parent; kw...)
    end
end

function get_pubpoint(rf::RPKIFile{CER}; rsync=false) :: AbstractString
    if !isnothing(rf.object.rrdp_notify) && !rsync
        split_scheme_uri(rf.object.rrdp_notify)[1]
    else
        split_scheme_uri(rf.object.pubpoint)[1]
    end
end


"""
	MFT <: RPKIObject

Represents a decoded manifest (.mft) file.

Fields:

Extracted from decoded file:
 - `files` -- `Vector{String}` containing filenames listed on this manifest
 - `loops` -- `Vector{String}` or `Nothing` listing the filenames causing a loop
 - `missing_files` -- `Vector{String}` of filenames listed in the manifest but not found on disk
 - `this_update`: `DateTime`
 - `next_update`: `DateTime`
"""
mutable struct MFT <: RPKIObject
    files::Vector{String}
    loops::Union{Nothing, Vector{String}}
    missing_files::Union{Nothing, Vector{String}}
    this_update::Union{Nothing, DateTime}
    next_update::Union{Nothing, DateTime}

end
MFT() = MFT(String[], nothing, nothing, nothing, nothing)

"""
	CRL <: RPKIObject

Represents a decoded Certificate Revocation List (.crl) file.

Fields:

 - `revoked_serials` -- Vector of [`SerialNumber`](@ref)'s
 - `this_update` -- `DateTime`
 - `next_update` -- `DateTime`

"""
mutable struct CRL <: RPKIObject
    revoked_serials::Vector{SerialNumber} # TODO also include Revocation Date for each serial
    this_update::Union{Nothing, DateTime}
    next_update::Union{Nothing, DateTime}
end
CRL() = CRL(SerialNumber[], nothing, nothing)
Base.show(io::IO, crl::CRL) = print(io, crl.this_update, " -> ", crl.next_update, "\n", crl.revoked_serials)


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
	ROA <: RPKIObject

Represents a decoded Route Origin Authorization (.roa) file.

Fields:

 - `asid` -- Integer
 - `vrp_tree` -- [`VRPS`](@ref)
 - `resources_v6` -- `IntervalTree{IPv6}` of the IPv6 resources in the EE certificate
 - `resources_v4` -- `IntervalTree{IPv4}` of the IPv4 resources in the EE certificate

After validation:
 - `resources_valid` -- Bool or Nothing
"""
mutable struct ROA <: RPKIObject
    asid::AutSysNum
    vrp_tree::VRPS
    resources_valid::Union{Nothing,Bool}
    resources_v6::Union{Nothing, IntervalTree{IPv6}} # TODO should we store these? or move to tpi?
    resources_v4::Union{Nothing, IntervalTree{IPv4}} # TODO should we store these?
end
ROA() = ROA(AutSysNum(0), VRPS(), # FIXME the AS0 here is ugly
            nothing,
            IntervalTree{IPv6, Interval{IPv6}}(),
            IntervalTree{IPv4, Interval{IPv4}}(),
           )


struct UnknownType <: RPKIObject end


function load(t::Type{T}, fn::AbstractString, parent::Union{Nothing, RPKIFile}=nothing) where {T<:RPKIObject}
    if !isfile(fn)
        @error "File not found: [$(nameof(T))] $(fn)"
        return nothing
    else
        asn1_tree = parse_file_recursive(fn)
        obj = t()
        return RPKIFile(parent, nothing, obj, fn, asn1_tree)
    end
end
function load(fn::AbstractString, parent::Union{Nothing, RPKIFile}=nothing)
    if endswith(fn, r"\.cer"i)
        load(CER, fn, parent)
    elseif endswith(fn, r"\.mft"i)
        load(MFT, fn, parent)
    elseif endswith(fn, r"\.crl"i)
        load(CRL, fn, parent)
    elseif endswith(fn, r"\.roa"i)
        load(ROA, fn, parent)
    else
        load(UnknownType, fn, parent)
    end
end

#include("Lookup.jl")

Base.@kwdef struct GlobalProcessInfo
    lock::ReentrantLock = ReentrantLock() 
    #transport::Transport = rsync::Transport
    transport::Transport = rrdp::Transport
    fetch_data::Bool = false
    data_dir::String = if transport == rsync
        CFG["rpki"]["rsync_data_dir"]
    elseif transport == rrdp
        CFG["rpki"]["rrdp_data_dir"]
    else
        ""
    end::String

    #tal::Union{Nothing, TAL} = nothing
    #lookup::Lookup = Lookup()
    nicenames::Bool = false
    strip_tree::Bool = false
    oneshot::Bool = false

    fetch_tasks::Dict{RPKIUri}{Task} = Dict{RPKIUri}{Task}()
    tasks::Vector{Task} = Task[]
end

#TODO can we make specific ones, per RPKIObject type, perhaps isbits/immutable?
Base.@kwdef mutable struct TmpParseInfo
    eContent::Union{Nothing,Node} = nothing
    signedAttrs::Union{Nothing,Node} = nothing  #TODO currently not used
    saHash::Union{Nothing, SVector{32, UInt8}} = nothing

    ee_cert::Union{Nothing,Node} = nothing
    ee_sig::Union{Nothing,Node} = nothing

    ee_rsaExponent::Union{Nothing,Node} = nothing
    ee_rsaModulus::Union{Nothing,Node} = nothing

    # TODO make these point to Node's as well?
    ee_aki::Union{Nothing, SVector{20, UInt8}} = nothing
    ee_ski::Union{Nothing, SVector{20, UInt8}} = nothing

    # for ROA:
    afi::UInt32 = 0x0
    # to verify CMS digest in MFT/ROAs:
    cms_message_digest::Union{Nothing, String} = "" #TODO SVector?
end

include("../PKIX/PKIX.jl")

using JDR.ASN1: childcount
#using .PKIX.X509
function check_ASN1(rf::RPKIFile{CER}, gpi::GlobalProcessInfo)
    # The certificate should consist of three parts: (RFC5280)
	# Certificate  ::=  SEQUENCE  {
	#      tbsCertificate       TBSCertificate,
	#      signatureAlgorithm   AlgorithmIdentifier,
	#      signature            BIT STRING  }
    
    childcount(rf.asn1_tree, 3) # this one marks the SEQUENCE as checked!
    
    tpi = TmpParseInfo() 
    tbsCertificate = rf.asn1_tree.children[1]
    X509.check_ASN1_tbsCertificate(rf, tbsCertificate, gpi, tpi)
    #TODO:
    X509.check_ASN1_signatureAlgorithm(rf, rf.asn1_tree.children[2], gpi, tpi)
    X509.check_ASN1_signatureValue(rf, rf.asn1_tree.children[3], gpi, tpi)
end

struct DelayedProcess
    uri_to_fetch::RPKIUri
    rf::RPKIFile{CER}
end

function process(rf::RPKIFile{CER}, gpi::GlobalProcessInfo) :: Union{Nothing, DelayedProcess}
    processing_delayed = false
    if !isnothing(rf.object.manifest)
        processing_delayed = true
    else
        check_ASN1(rf, gpi)
        if !gpi.oneshot
            check_sig(rf)
            check_resources(rf)
        end
    end

    @assert !isempty(rf.object.manifest)

    # check if we hop to another CA
    traverse_ca = !gpi.oneshot && (rf.parent.object isa RootCER || get_pubpoint(rf.parent.parent) != get_pubpoint(rf))
    if traverse_ca && gpi.fetch_data
        uri_to_fetch = if !isnothing(rf.object.rrdp_notify)
            rf.object.rrdp_notify
        else
            rf.object.pubpoint
        end::RPKIUri
        lock(gpi.lock)
        try
            if !(haskey(gpi.fetch_tasks, uri_to_fetch) && istaskdone(gpi.fetch_tasks[uri_to_fetch]))
                @assert !processing_delayed
                return DelayedProcess(uri_to_fetch, rf)
            end
        finally
            unlock(gpi.lock)
        end
    end

    mft_fn = joinpath(gpi.data_dir, @view rf.object.manifest[9:end])
    if isfile(mft_fn)
        mft = load(MFT, mft_fn, rf)
        rf.children = mft
    else
        @warn "Manifest not on filesystem: $(mft_fn)"
        remark_missingFile!(rf, "Manifest not on filesystem: $(mft_fn)")
    end
    gpi.strip_tree && (rf.asn1_tree = nothing)
    return nothing
end

function get_parent_cer(rf::RPKIFile{CER}) :: Union{Nothing, CER}
    if !isnothing(rf.parent) && !isnothing(rf.parent.parent)
        rf.parent.parent.object
    else
        nothing
    end
end
function get_parent_cer(rf::RPKIFile{ROA}) :: Union{Nothing, CER}
    if !isnothing(rf.parent) && !isnothing(rf.parent.parent)
        rf.parent.parent.object
    else
        nothing
    end
end
function check_sig(rf::RPKIFile{CER})
    # TODO: make this work the other way around?
    #   - take a 'parent CER' and process all the (grand)children 
    #   however with the current asn1_tree.buf.data approach that does not
    #   reduce the number of file open syscalls or whatever..

    parent_cer = get_parent_cer(rf)
    if !rf.object.selfsigned && parent_cer.subject != rf.object.issuer
        @error "subject != issuer for child cert $(rf.filename)"
        remark_validityIssue!(rf, "subject != issuer for child cert")
    end
    sig = rf.asn1_tree.children[3]::Node
    signature = to_bigint(@view sig.tag.value[2:end])::BigInt
    @assert !isnothing(rf.object.selfsigned)
    v = if rf.object.selfsigned
        powermod(signature, rf.object.rsa_exp, rf.object.rsa_modulus)
    else
        powermod(signature, parent_cer.rsa_exp, parent_cer.rsa_modulus)
    end::BigInt
    v.size = 4
    v_str = string(v, base=16, pad=64)

    tbs_raw = @view rf.asn1_tree.buf.data[rf.asn1_tree[1].tag.offset_in_file:rf.asn1_tree[2].tag.offset_in_file-1]
    my_hash = bytes2hex(sha256(tbs_raw))

    # this only described whether the signature is valid or not! no resource
    # checks done at this point
    if v_str != my_hash
        remark_validityIssue!(rf, "Invalid signature")
    end
    return nothing
end

function check_resources(rf::RPKIFile{CER})
    # First, check coverage of ASNs in the parent chain
    #
    rf.object.resources_valid = true
    parent_cer = rf.parent.parent
    if !rf.object.selfsigned
        if !covered(rf.object.ASNs , parent_cer.object.ASNs)
            _covered = false
            # not covered, so check for inherited ASNs in parent certificates
            while ((parent_cer = parent_cer.parent.parent) !== nothing) # FIXME check for RootCER

                if !parent_cer.object.inherit_ASNs
                    if !covered(rf.object.ASNs, parent_cer.object.ASNs)
                        @warn "illegal ASNs for $(rf.filename)"
                        remark_validityIssue!(o, "illegal ASNs")
                        rf.object.resources_valid = false
                    end
                    _covered = true
                    break
                end
            end
            if !_covered
                # The only way to reach this is if any of the RIR certs has no
                # ASNs (which is already wrong) and also no inheritance
                @error "ASN inheritance chain illegal for $(rf.filename)"
            end
        end
    end

    # now for the prefixes
    # TODO what do we do if the object is self signed?
    if !rf.object.selfsigned
        p_cer_v6 = p_cer_v4 = rf.parent.parent
        if isempty(rf.object.resources_v6) 
            if isnothing(rf.object.inherit_v6_prefixes)
                #@warn "v6 prefixes empty, but inherit bool is not set.."
                #@error "empty v6 prefixes undefined inheritance? $(rf.filename)"
            elseif !(rf.object.inherit_v6_prefixes)
                @error "empty v6 prefixes and no inheritance? $(rf.filename)"
                remark_resourceIssue!(o, "No IPv6 prefixes and no inherit flag set")
            end
        else
            while (p_cer_v6.object.inherit_v6_prefixes)
                p_cer_v6 = p_cer_v6.parent.parent
            end
        end

        if isempty(rf.object.resources_v4) 
            if isnothing(rf.object.inherit_v4_prefixes)
                #@warn "v4 prefixes empty, but inherit bool is not set.."
                #@error "empty v4 prefixes undefined inheritance? $(rf.filename)"
            elseif !(rf.object.inherit_v4_prefixes)
                @error "empty v4 prefixes and no inheritance? $(rf.filename)"
                remark_resourceIssue!(o, "No IPv4 prefixes and no inherit flag set")
            end
        else
            while (p_cer_v4.object.inherit_v4_prefixes)
                p_cer_v4 = p_cer_v4.parent.parent
            end
        end

        
        # IPv6:
		check_coverage(p_cer_v6.object.resources_v6, rf.object.resources_v6) do invalid
            @warn "illegal IP resource $(IPRange(invalid.first, invalid.last)) on $(rf.filename)"
            remark_resourceIssue!(rf, "Illegal IPv6 resource $(IPRange(invalid.first, invalid.last))")
            rf.object.resources_valid = false
        end

        # IPv4:
        check_coverage(p_cer_v4.object.resources_v4, rf.object.resources_v4) do invalid
            @warn "illegal IP resource $(IPRange(invalid.first, invalid.last)) on $(rf.filename)"
            remark_resourceIssue!(rf, "Illegal IPv4 resource $(IPRange(invalid.first, invalid.last))")
            rf.object.resources_valid = false
        end
    end

end



include("../PKIX/CMS.jl")
include("MFT.jl")
function check_ASN1(rf::RPKIFile{MFT}, gpi::GlobalProcessInfo) :: TmpParseInfo
    tpi = TmpParseInfo()
    cmsobject = rf.asn1_tree
    # CMS, RFC5652:
    #       ContentInfo ::= SEQUENCE {
    #           contentType ContentType,
    #           content [0] EXPLICIT ANY DEFINED BY contentType }
    
    check_tag(cmsobject, SEQUENCE)
    childcount(cmsobject, 2)

    # from CMS.jl:
    CMS.check_ASN1_contentType(rf, cmsobject[1], gpi, tpi)
    CMS.check_ASN1_content(rf, cmsobject[2], gpi, tpi)

    Mft.check_ASN1_manifest(rf, tpi.eContent, gpi, tpi)
    tpi
end

function process(rf::RPKIFile{MFT}, gpi::GlobalProcessInfo)
    tpi = check_ASN1(rf, gpi)
    if !gpi.oneshot
        check_sig(rf, tpi)
    else
        @warn "oneshotting $(basename(rf.filename)), not checking EE signature"
    end

    # for each of listed files, load() CER/CRL/ROA
    rf.children = RPKIFile[]
    for f in rf.object.files
        # every file in .files exists, checked in Mft.jl
        mft_path = dirname(rf.filename)
        fn = joinpath(mft_path, f)
        push!(rf.children, load(fn, rf))
    end

    gpi.strip_tree && (rf.asn1_tree = nothing)
    rf
end

function check_sig(rf::RPKIFile{MFT}, tpi::TmpParseInfo)
    # hash tpi.eeCert
    @assert !isnothing(tpi.ee_cert)
    tbs_raw = @view rf.asn1_tree.buf.data[tpi.ee_cert.tag.offset_in_file:tpi.ee_cert.tag.offset_in_file + tpi.ee_cert.tag.len + 4 - 1]
    my_hash = bytes2hex(sha256(tbs_raw))

    # decrypt tpi.ee_sig 
    v = powermod(to_bigint(@view tpi.ee_sig.tag.value[2:end]), rf.parent.object.rsa_exp, rf.parent.object.rsa_modulus)
    v.size = 4
    v_str = string(v, base=16, pad=64)
    
    # compare hashes
    if v_str != my_hash
        @error "invalid EE signature for" rf.filename
        remark_validityIssue!(rf, "invalid signature on EE certificate")
    end
end



include("CRL.jl")
function check_ASN1(rf::RPKIFile{CRL}, gpi::GlobalProcessInfo)
	# CertificateList  ::=  SEQUENCE  {
	#  tbsCertList          TBSCertList,
	#  signatureAlgorithm   AlgorithmIdentifier,
	#  signatureValue       BIT STRING  }
    
    tpi = TmpParseInfo()
    childcount(rf.asn1_tree, 3)

    Crl.check_ASN1_tbsCertList(rf, rf.asn1_tree.children[1], gpi, tpi)
    # from X509.jl:
    X509.check_ASN1_signatureAlgorithm(rf, rf.asn1_tree.children[2], gpi, tpi)
    X509.check_ASN1_signatureValue(rf, rf.asn1_tree.children[3], gpi, tpi)
end

function check_sig(rf::RPKIFile{CRL})
    sig = rf.asn1_tree.children[3]
    signature = to_bigint(@view sig.tag.value[2:end])
    v = powermod(signature, rf.parent.parent.object.rsa_exp, rf.parent.parent.object.rsa_modulus)
    v.size = 4
    v_str = string(v, base=16, pad=64)

    tbs_raw = @view rf.asn1_tree.buf.data[rf.asn1_tree[1].tag.offset_in_file:rf.asn1_tree[2].tag.offset_in_file-1]
    my_hash = bytes2hex(sha256(tbs_raw))

    # compare hashes
    if v_str != my_hash
        remark_validityIssue!(rf, "Invalid signature")
    end
end

function process(rf::RPKIFile{CRL}, gpi::GlobalProcessInfo)
    check_ASN1(rf, gpi)
    if !gpi.oneshot
        check_sig(rf)
    end
    # no children
    #
    gpi.strip_tree && (rf.asn1_tree = nothing)
end

include("ROA.jl")
add_resource!(roa::ROA, ipr::IPRange{IPv6}) = push!(roa.resources_v6, Interval(ipr))
add_resource!(roa::ROA, ipr::IPRange{IPv4}) = push!(roa.resources_v4, Interval(ipr))
function check_ASN1(rf::RPKIFile{ROA}, gpi::GlobalProcessInfo) :: TmpParseInfo
    cmsobject = rf.asn1_tree
    # CMS, RFC5652:
    #       ContentInfo ::= SEQUENCE {
    #           contentType ContentType,
    #           content [0] EXPLICIT ANY DEFINED BY contentType }
    
    tpi = TmpParseInfo()
    check_tag(cmsobject, SEQUENCE)
    childcount(cmsobject, 2)

    # from CMS.jl:
    CMS.check_ASN1_contentType(rf, cmsobject[1], gpi, tpi)
    CMS.check_ASN1_content(rf, cmsobject[2], gpi, tpi)

    Roa.check_ASN1_routeOriginAttestation(rf, tpi.eContent, gpi, tpi)
    tpi
end

function check_sig(rf::RPKIFile{ROA}, tpi::TmpParseInfo)
    # hash tpi.eeCert
    @assert !isnothing(tpi.ee_cert)
    tbs_raw = @view rf.asn1_tree.buf.data[tpi.ee_cert.tag.offset_in_file:tpi.ee_cert.tag.offset_in_file + tpi.ee_cert.tag.len + 4 - 1]
    my_hash = bytes2hex(sha256(tbs_raw))

    # decrypt tpi.eeSig 
    v = powermod(to_bigint(@view tpi.ee_sig.tag.value[2:end]), rf.parent.parent.object.rsa_exp, rf.parent.parent.object.rsa_modulus)
    v.size = 4
    v_str = string(v, base=16, pad=64)
    
    # compare hashes
    if v_str != my_hash
        @error "Invalid EE signature for" rf.filename
        remark_validityIssue!(rf, "Invalid signature on EE certificate")
    end
end


function check_resources(rf::RPKIFile{ROA})
    # TODO: check out intersect(t1::IntervalTree, t2::IntervalTree) and find any
    # underclaims?
    rf.object.resources_valid = true

    # first, check the resources on the EE are properly covered by the resources
    # in the parent CER
    # TODO: check: can the parent cer have inherit set instead of listing actual
    # resources?

    #v6:
    if !isempty(rf.object.resources_v6)
        overlap_v6 = collect(intersect(get_parent_cer(rf).resources_v6, rf.object.resources_v6))
        if length(overlap_v6) == 0
            @warn "IPv6 resource on EE in $(rf.filename) not covered by parent certificate $(get_parent_cer(rf).subject)"
            remark_resourceIssue!(rf, "IPv6 resource on EE not covered by parent certificate")
            rf.object.resources_valid = false
        else
            for (p, ee) in overlap_v6
                if !(p.first <= ee.first <= ee.last <= p.last)
                    @warn "IPv6 resource on EE in $(rf.filename) not properly covered by parent certificate"
                    remark_resourceIssue!(rf, "Illegal IP resource $(ee)")
                    rf.object.resources_valid = false
                end
            end
        end
    end

    #v4:
    if !isempty(rf.object.resources_v4)
        overlap_v4 = collect(intersect(get_parent_cer(rf).resources_v4, rf.object.resources_v4))
        if length(overlap_v4) == 0
            @warn "IPv4 resource on EE in $(rf.filename) not covered by parent certificate $(get_parent_cer(rf).subject)"
            remark_resourceIssue!(rf, "IPv4 resource on EE not covered by parent certificate")
            rf.object.resources_valid = false
        else
            for (p, ee) in overlap_v4
                if !(p.first <= ee.first <= ee.last <= p.last)
                    @warn "IPv4 resource on EE in $(rf.filename) not properly covered by parent certificate"
                    remark_resourceIssue!(rf, "Illegal IP resource $(ee)")
                    rf.object.resources_valid = false
                end
            end
        end
    end

    # now that we know the validity of the resources on the EE, verify that the
    # VRPs are covered by the resources on the EE

    # IPv6:
    check_coverage(rf.object.resources_v6, rf.object.vrp_tree.resources_v6) do invalid
        @warn "illegal IPv6 VRP $(IPRange(invalid.first, invalid.last)) not covered by EE on $(rf.filename)"
        remark_resourceIssue!(rf, "Illegal IPv6 VRP $(IPRange(invalid.first, invalid.last))")
        rf.object.resources_valid = false
    end

    # IPv4:
    check_coverage(rf.object.resources_v4, rf.object.vrp_tree.resources_v4) do invalid
        @warn "illegal IPv4 VRP $(IPRange(invalid.first, invalid.last)) not covered by EE on $(rf.filename)"
        remark_resourceIssue!(rf, "Illegal IPv4 VRP $(IPRange(invalid.first, invalid.last))")
        rf.object.resources_valid = false
    end
end

function process(rf::RPKIFile{ROA}, gpi::GlobalProcessInfo)
    tpi = check_ASN1(rf, gpi)
    if !gpi.oneshot
        check_sig(rf, tpi)
        check_resources(rf)
    end
    # no children
    gpi.strip_tree && (rf.asn1_tree = nothing)
end

function process(rf::RPKIFile{UnknownType}, ::GlobalProcessInfo)
    @warn "No implementation to process $(basename(rf.filename))"
    # no children
end

function oneshot(filename::AbstractString; gpi_kw...)
    if !isfile(filename)
        @error "oneshot: $(filename) does not exist"
        display(stacktrace(catch_backtrace()))
        throw("oneshot: $(filename) does not exist")
    end
    rf = load(filename)
    gpi = GlobalProcessInfo(; strip_tree = false, nicenames = false, gpi_kw..., oneshot = true)
    process(rf, gpi)
    rf
end


include("rsync.jl")
include("RRDP.jl")


function process_all(rf::RPKIFile, gpi=GlobalProcessInfo()) :: RPKIFile
    todo_c = Channel{RPKIFile}(50000)
    put!(todo_c, rf)
    total = 0
    #res = 0
    while(isready(todo_c))
        total += 1
        c = take!(todo_c)
        try
            res = RPKI.process(c, gpi)
            if res isa DelayedProcess
                lock(gpi.lock)
                try
                    if !haskey(gpi.fetch_tasks, res.uri_to_fetch)
                        fetch_t = if gpi.transport == rrdp
                            if !isnothing(c.object.rrdp_notify)
                                @async try
                                    RRDP.fetch_process_notification(c)
                                catch e
                                    @warn e c.object.rrdp_notify
                                end
                            else
                                @warn "Need to fetch for $(c) but no RRDP available"
                                @async ()
                            end
                        elseif gpi.transport == rsync
                            @error "TODO implement rsync fetch here"
                            throw("Implement rsync fetch in process_all")
                        end
                        isnothing(res) && @error "#1 res isnothing"
                        gpi.fetch_tasks[res.uri_to_fetch] = fetch_t
                    end
                    new_process_all_t = @async begin
                        wait(gpi.fetch_tasks[res.uri_to_fetch])
                        process_all(res.rf, gpi)
                    end
                    push!(gpi.tasks, new_process_all_t)

                finally
                    unlock(gpi.lock)
                end
            elseif !isnothing(c.children)
                if !isnothing(c.children)
                    if c.children isa Vector
                        for _c in c.children
                            put!(todo_c, _c)
                        end
                    else
                        put!(todo_c, c.children)
                    end
                end
            end
        catch e
            @error "exception $(typeof(e)) in process_all for $(c.filename)"
            remark_genericError!(c, "$(typeof(e)) while processing")
            continue
        end
    end
    rf
end

function process_tas(tals=CFG["rpki"]["tals"];gpi_kw...)
    if isempty(tals)
        @warn "No TALs configured, please create/edit JDR.toml and run

            JDR.Config.generate_config()

        "
        return nothing
    end

    root = RPKIFile()
    gpi = GlobalProcessInfo(strip_tree = true; gpi_kw...)

    # first, parse all TALs and collect ta_cer_fns
    # if fetch_data, fetch all TA cers
    ta_cer_fns = AbstractString[]

    @sync for (talname, tal_fn) in tals
        tal = parse_tal(joinpath(CFG["rpki"]["tal_dir"], tal_fn))
        ta_cer_uri = if gpi.transport == rsync
            tal.rsync
        elseif gpi.transport == rrdp
            tal.rrdp
        else
            @error "Unknown transport $(gpi.transport) while processing TAL $(talname)"
            continue
        end
        ta_cer_fn = joinpath(gpi.data_dir, @view ta_cer_uri.u[9:end])
        push!(ta_cer_fns, ta_cer_fn)
        if gpi.fetch_data
            @async RRDP.fetch_ta_cer(ta_cer_uri, ta_cer_fn)
        end
    end
    @debug ta_cer_fns
        
    # now process
    for ta_fn in ta_cer_fns
        ta_rf = load(RPKI.CER, ta_fn, root)
        if isnothing(ta_rf)
            @warn "something wrong with $(ta_fn), skipping"
            continue
        end
        push!(root.children, ta_rf)
        t = Threads.@spawn process_all(ta_rf, gpi)
        lock(gpi.lock)
        try
            push!(gpi.tasks, t)
        finally
            unlock(gpi.lock)
        end
    end
    @debug "gpi.tasks: $(length(gpi.tasks))"

    outtimer = @async begin
        try
            @info "pre timedwait"
            status = timedwait(() ->
                               all(istaskdone, gpi.tasks) &&
                               all(t->istaskdone(t.second), gpi.fetch_tasks)
                              , 300; pollint=5)
            @info "post timedwait"
            
            @warn 1 status
            if status == :timed_out
                for (url, task) in filter(t->!istaskdone(t.second), gpi.fetch_tasks)
                    @warn "Interrupting fetch for $(url)"
                    println("Interrupting fetch for $(url)")
                    schedule(task, InterruptException(); error=true)
                    #wait(task)
                end
                for t in filter(!istaskdone, gpi.tasks)
                    @warn "Interrupting task $(t)"
                    println("Interrupting task $(t)")
                    schedule(t, InterruptException(); error=true)
                    #wait(t)
                end
            else
                @info "------------------------------------------------------------"
                @info " All (fetch) tasks completed before timeout"
                @info "------------------------------------------------------------"
            end
        catch e
            @error e
        end
    end

    @info "pre wait(outtimer)"
    wait(outtimer)
    @info "post wait(outtimer)"
    
    done = false
    i = 0
    while !done
        lock(gpi.lock)
        try
            done = all(istaskdone, gpi.tasks)
            if i % 10 == 0 
                #@info "waiting for $(count(!istaskdone, gpi.tasks))/$(length(gpi.tasks))"
                if count(!istaskdone, values(gpi.fetch_tasks)) <= 5
                    print("\r [$(now())] waiting for $(count(!istaskdone, gpi.tasks))/$(length(gpi.tasks)) tasks, and fetches: ", 
                            map(e -> e.first.u, collect(filter(e->!istaskdone(e.second), gpi.fetch_tasks)))
                           )
                end
            end

        finally
            unlock(gpi.lock)
        end
        sleep(0.1)
        i += 1
        i %= 10
    end

    @debug "gpi.tasks done: $(count(istaskdone, gpi.tasks))"
    @debug "pre foreach wait gpi.tasks"
    # call wait() to get any lingering outputs/errors
    for t in gpi.tasks
        try
            wait(t)
        catch e
            @warn typeof(e)
        end
    end
    #foreach(wait, gpi.tasks)
    @debug "post foreach wait"
    #results = map((t) -> t.result, gpi.tasks)
    #@debug results

    @debug "one more time, gpi.tasks: $(length(gpi.tasks))"
    #@debug "gpi.fetch_tasks ($(length(keys(gpi.fetch_tasks)))): $(keys(gpi.fetch_tasks))"

    
    root, gpi
end


##############################
# end of refactor
##############################


#=



"""
    check_ASN1

Validate ASN1 structure of an [`RPKIObject`](@ref). Method definitions in [CER.jl](@ref) etc.
"""


struct LoopError <: Exception 
    file1::String
    file2::String
end
LoopError(file1::String) = LoopError(file1, "")
Base.showerror(io::IO, e::LoopError) = print(io, "loop between ", e.file1, " and ", e.file2)

function link_resources!(cer::RPKINode)
    if isnothing(cer.children)
        return
    end

    # There are two cases when traversing down the RPKINode tree:
    # 1: a CER points, via an MFT (.children[1]), to children
    # 2: the RootCER points to RIR CERs directly
    descendants = if cer.children[1].obj.object isa MFT
        # case 1
        cer.children[1].children
    elseif cer.obj.object isa RootCER
        # case 2
        cer.children
    end
    for child in filter(x->x.obj.object isa Union{CER,ROA}, descendants)
        overlap = intersect(cer.obj.object.resources_v6, child.obj.object.resources_v6)
        for (p, c) in overlap
            push!(p.value, child) # add RPKINode pointing to child to this interval.value
        end
        overlap = intersect(cer.obj.object.resources_v4, child.obj.object.resources_v4)
        for (p, c) in overlap
            push!(p.value, child) # add RPKINode pointing to child to this interval.value
        end
        if child.obj.object isa CER
            link_resources!(child)
        elseif child.obj.object isa ROA
            #@warn "not linking EE -> VRP" maxlog=3
            
            # now we can get rid of the EE tree, roa.resources_v6/_v4
            #@warn "setting EE resources to nothing" maxlog=3
            child.obj.object.resources_v6 = nothing
            child.obj.object.resources_v4 = nothing
        end
    end
end


"""
	process_ta(ta_cer_fn::String; kw...)

Takes a first cerficate to parse and processes all related descending files.
Called by [`process_tas`](@ref).


Optional keyword arguments:

 - `repodir::String` -- defaults to `CFG["rpki"]["rsyncrepo"]`, i.e. the `JDR.toml` config file.
    Useful for processing data that is stored in a non-default directory structure, for
    example when the TA certificate is stored in a different directory than the RPKI files.
 - `lookup` -- defaults to an empty `Lookup()`
 - `stripTree::Bool` -- drop the ASN.1 tree from objects after validation, defaults to `false`
 - `nicenames::Bool` -- enrich the ASN.1 tree with human-readable fieldnames, defaults to `true`

Returns `Tuple{`[`RPKINode`](@ref)`,`[`Lookup`](@ref)`}`
"""

"""
    process_tas([tal_urls::Dict]; kw...)

Process all trust anchors configured in `JDR.toml`. This is likely the most common way to
start doing anything using `JDR.jl`:

```julia
using JDR;
(tree, lookup) = process_tas()
```

Optionally, a `Dict` of similar form can be passed directly to specify trust anchors not in
the configuration file, or a subset of those that are specified.

Optional keyword arguments:

 - `repodir::String` -- defaults to `CFG["rpki"]["rsyncrepo"]`, i.e. the `JDR.toml` config file. 
 - `stripTree::Bool` -- drop the ASN.1 tree from objects after validation, defaults to `false`
 - `nicenames::Bool` -- enrich the ASN.1 tree with human-readable fieldnames, defaults to `true`

Returns `Tuple{`[`RPKINode`](@ref)`,`[`Lookup`](@ref)`}`

"""

function collect_remarks_from_asn1!(o::RPKIObject{T}, node::Node) where T
    if !isnothing(node.remarks)
        if isnothing(o.remarks_tree)
            o.remarks_tree = []
        end
        Base.append!(o.remarks_tree, node.remarks)
    end
    if !isnothing(node.children)
        for c in node.children
            collect_remarks_from_asn1!(o, c)
        end
    end
end

=# # end of refactor tmp comment block

end # module
