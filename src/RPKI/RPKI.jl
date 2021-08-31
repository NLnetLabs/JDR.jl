module RPKI
using TimerOutputs
using JDR: CFG
using JDR.Common: RPKIUri, NotifyUri, RsyncUri
using JDR.Common: Remark, RemarkCounts_t, split_scheme_uri, count_remarks, AutSysNum, IPRange
using JDR.Common: remark_missingFile!, remark_loopIssue!, remark_manifestIssue!, remark_validityIssue!
#using JDR.RPKICommon: add_resource!, RPKIObject, RPKINode, Lookup, TmpParseInfo, add_filename!
#using JDR.RPKICommon: CER, add_resource, MFT, CRL, ROA, add_missing_filename!, RootCER, get_pubpoint
#using JDR.RPKICommon: get_object, rsync, rrdp, parse_tal
using JDR.ASN1: Node, SEQUENCE, check_tag

#using IntervalTrees: IntervalValue, IntervalMap
using Sockets: IPAddr

export process_tas, process_ta, process_cer, link_resources!
export RPKIFile



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
    #notify_domains = Dict{AbstractString}{Vector{RPKIFile}}()

    #last_hostname = get_pubpoint(rf)
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
        this_pp = get_pubpoint(rf)
        last_pp = if !isnothing(rf.parent)
            get_pubpoint(rf.parent)
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
    
    #if f.object isa CER
    #        this_hostname = get_pubpoint(f)
    #        if this_hostname != last_hostname
    #            if haskey(pubpoints, this_hostname)
    #                push!(pubpoints[this_hostname], f)
    #            else
    #                pubpoints[this_hostname] = [f]
    #            end
    #            last_hostname == this_hostname
    #        end
    #    end
    #end
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
function get_pubpoint(rf::RPKIFile) :: AbstractString
    #@debug "get_pubpoint for $(rf)"
    if rf.object isa RootCER
        return "root"
    end
    return if rf.object isa MFT 
        @assert rf.parent.object isa CER
        get_pubpoint(rf.parent)
    else #if rf.object isa ROA || rf.object isa CRL
        @assert rf.parent.object isa MFT
        @assert rf.parent.parent.object isa CER
        get_pubpoint(rf.parent.parent)
    end
end

function get_pubpoint(rf::RPKIFile{CER}) :: AbstractString
    if !isnothing(rf.object.rrdp_notify)
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




#function load(t::Type{T}, fn::AbstractString, parent=Union{Nothing, RPKIFile}=nothing) :: RPKIFile{<:RPKIObject} where {T<:RPKIObject}
function load(t::Type{T}, fn::AbstractString, parent::Union{Nothing, RPKIFile}=nothing) where {T<:RPKIObject}
    if !isfile(fn)
        @error "File not found: [$(nameof(T))] $(fn)"
        #@debug "parent is: $(parent)"
        #throw("stop")
        return nothing
        #return RPKIFile(parent, nothing, UnknownType(), fn, nothing)
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

    #caCert::Union{Nothing,Node} = nothing

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
    childcount(rf.asn1_tree, 3) # this one marks the SEQUENCE as checked!
    #@debug typeof(rf)
    
    tpi = TmpParseInfo() 
    tbsCertificate = rf.asn1_tree.children[1]
    X509.check_ASN1_tbsCertificate(rf, tbsCertificate, gpi, tpi)
    #TODO:
    X509.check_ASN1_signatureAlgorithm(rf, rf.asn1_tree.children[2], gpi, tpi)
    X509.check_ASN1_signatureValue(rf, rf.asn1_tree.children[3], gpi, tpi)
end

function fake_fetch(url::RPKIUri)
    try
        @info "fake_fetching $(url)"
        t = rand()*0.1
        sleep(t)
        @info "fake_fetching $(url) done after $(t)"
    catch e
        @error e url
    end
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
    traverse_ca = rf.parent.object isa RootCER || get_pubpoint(rf.parent.parent) != get_pubpoint(rf)
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
            #if !(rf.object.rrdp_notify in keys(gpi.fetch_tasks) && istaskdone(gpi.fetch_tasks[rf.object.rrdp_notify]))
            #    @assert !processing_delayed
            #    return DelayedProcess(rf.object.rrdp_notify, rf)
            #end
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
function check_sig(rf::RPKIFile{CER})#, tpi::TmpParseInfo, parent_cer::Union{Nothing, RPKINode}=nothing)# :: RPKIObject{CER}
    # TODO: make this work the other way around?
    #   - take a 'parent CER' and process all the (grand)children 
    #   however with the current asn1_tree.buf.data approach that does not
    #   reduce the number of file open syscalls or whatever..

    #parent_cer = rf.parent.parent.object::CER
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

function check_resources(rf::RPKIFile{CER})#, tpi::TmpParseInfo, parent_cer::Union{Nothing, RPKINode}=nothing)
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
    # TODO skip check_sig when oneshotting
    if !gpi.oneshot
        check_sig(rf, tpi)
    else
        @warn "oneshotting $(basename(rf.filename)), not checking EE signature"
    end
    # for each of listed files, load() CER/CRL/ROA
    
    #children = map(fn -> load(fn, rf), rf.object.files)
    rf.children = RPKIFile[]
    for f in rf.object.files
        # every file in .files exists, checked in Mft.jl
        mft_path = dirname(rf.filename)
        fn = joinpath(mft_path, f)
        push!(rf.children, load(fn, rf))
    end

    # push to children (Vector)
    #rf.children = children
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

function check_sig(rf::RPKIFile{CRL})#, tpi::TmpParseInfo, parent_cer::RPKINode) :: RPKI.RPKIObject{CRL}
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


function check_resources(rf::RPKIFile{ROA})#, tpi::TmpParseInfo, parent_cer::RPKINode)
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
    #@debug "process_all for $(rf.filename), parent: $(rf.parent)"
    # TODO check if rf is already processed?
    #RPKI.process(rf, gpi)
    #todo = RPKIFile[rf]
    todo_c = Channel{RPKIFile}(50000)
    put!(todo_c, rf)
    #for c in todo
    total = 0
    while(isready(todo_c))
        total += 1
        #@debug "in todo for $(c)"
        c = take!(todo_c)
        res = RPKI.process(c, gpi)
        if res isa DelayedProcess
            #@debug "got a new DelayedProcess for $(res.notify_url)"
            lock(gpi.lock)
            try
                #if !(res.uri_to_fetch in keys(gpi.fetch_tasks))
                if !haskey(gpi.fetch_tasks, res.uri_to_fetch)
                    #TODO: distinguish between RRDP and rsync
                    #moreover, fallback to rsync here in case .rrdp_notify #isnothing?
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
                    gpi.fetch_tasks[res.uri_to_fetch] = fetch_t
                end
                new_process_all_t = @async begin
                    wait(gpi.fetch_tasks[res.uri_to_fetch])
                    #@debug "Spawned thread, wait done for $(res.uri_to_fetch)"
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
                        #push!(todo, _c)
                        put!(todo_c, _c)
                    end
                else
                    #push!(todo, c.children)
                    put!(todo_c, c.children)
                end
            end
        end
    end
    #@debug "process_all done ($(total) processed) for $(rf.filename)"
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
    #ta_cer_uris = RPKIUri[]
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
        

    #return nothing

    # now process
    #ta_cer_fns = [
    #       #"rrdp_repo/rpki.afrinic.net/repository/AfriNIC.cer",
    #       #"rrdp_repo/rpki.apnic.net/repository/apnic-rpki-root-iana-origin.cer",
    #       #"rrdp_repo/rpki.arin.net/repository/arin-rpki-ta.cer",
    #       #"rrdp_repo/repository.lacnic.net/rpki/lacnic/rta-lacnic-rpki.cer",
    #       "rrdp_repo/rpki.ripe.net/ta/ripe-ncc-ta.cer",
    #       ]
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


#=
function depr_process_ta(ta_cer_fn::AbstractString, root=RPKI.RPKIFile(); kw...)
    gpi = GlobalProcessInfo()
	#root = RPKI.RPKIFile() # creates a RootCer #TODO pass to this method as arg?
	cer_rf = RPKI.load(ta_cer_fn, root)
	RPKI.process(cer_rf, gpi)

	mft_rf = cer_rf.children
	@assert mft_rf.object isa RPKI.MFT
	RPKI.process(mft_rf, gpi)

	# now loop/recurse
	@assert mft_rf.children isa Vector

	tasks = Channel{RPKI.RPKIFile{<:RPKI.RPKIObject}}(50000)
	for c in mft_rf.children
		put!(tasks, c)
	end
	total = Threads.Atomic{Int}(2)

# TODO do_work() into a proper function?
	do_work(t_id) = begin
		@debug t_id "spawned do_work()"
		try
            c = nothing
            #while timedwait(() -> begin c = take!(tasks); true end, 5) == :ok
			while timedwait(() -> isready(tasks), 2) == :ok
				@debug t_id "in isready"
                if timedwait(() -> begin c = take!(tasks); true end, 1) == :timed_out
                    @debug "inner timed_out"
                    break
                end
                @debug t_id "post timedwait take!"
				#c = take!(tasks)
				Threads.atomic_add!(total, 1)
				RPKI.process(c, gpi)
                @debug t_id "post .process"
				if !isnothing(c.children)
					if c.children isa Vector
						for _c in c.children
							put!(tasks, _c)
						end
					else
						put!(tasks, c.children)
					end
				end
                @debug t_id "end of while"
			end
			@debug t_id "tasks notready"
		catch e
			@warn t_id e
            display(stacktrace(catch_backtrace()))
			throw(e)
		end
        @info t_id "task done"
	end
	worker_handles = []
	@debug "spawning tasks on $(Threads.nthreads()) threads"
	for i in 1:Threads.nthreads()
		_h = Threads.@spawn do_work(i)
		@assert !isnothing(_h)
		push!(worker_handles, _h)
	end
	@debug "waiting on $(length(worker_handles)) worker_handles"
	i = 0
	ind_symbols = ['|', '/', '-', '\\', '|', '/', '-', '\\']
	while !all(istaskdone, worker_handles)
		ind = ind_symbols[(i %= length(ind_symbols)) + 1]
		print("\r$(ind) $(count(istaskdone, worker_handles))/$(length(worker_handles)) done, $(count(istaskfailed, worker_handles)) failed, waiting")
		sleep(0.05)
		i += 1
	end
	@info "Done, processed $(total[]) files"
	@debug "pre foreach wait"
	foreach(wait, worker_handles) # to get errors/output
	@debug "post foreach wait"
	#@info "Making lookup"
	#global lookup
	#@time lookup = RPKI.Lookup(cer_rf)
end
=#

#=
function tmp_runall()
    gpi = GlobalProcessInfo()
    root_rf = RPKI.RPKIFile()
    tas = split("""
           rrdp_repo/rpki.afrinic.net/repository/AfriNIC.cer
           """
           #rrdp_repo/rpki.apnic.net/repository/apnic-rpki-root-iana-origin.cer
           #rrdp_repo/rpki.arin.net/repository/arin-rpki-ta.cer
           #rrdp_repo/repository.lacnic.net/rpki/lacnic/rta-lacnic-rpki.cer
           #rrdp_repo/rpki.ripe.net/ta/ripe-ncc-ta.cer
           #"""
           )
    #for ta_fn in tas
    #    @debug "calling process_ta for $(ta_fn)"
    #    @time process_ta(ta_fn)
    #end
    tasks = Vector{Task}()
    results = Channel(10)

    for ta_fn in tas
        talname = "TODO" # comes from config eventually
        #@debug "for talname: $(talname)"
        #=
        tal = parse_tal(joinpath(CFG["rpki"]["tal_dir"], ta_fn))
        cer_uri = if gpi.transport == rsync
            tal.rsync
        elseif gpi.transport == rrdp
            if isnothing(tal.rrdp)
                @warn "No RRDP URI for tal $(talname), skipping"
                continue
            end
            tal.rrdp
        end

        (hostname, cer_fn) = split_scheme_uri(cer_uri) 
        ta_cer_fn = joinpath(gpi.data_dir, "tmp", hostname, cer_fn)
        if !isfile(ta_cer_fn)
            if gpi.fetch_data
                if gpi.transport == rrdp
                    RRDP.fetch_ta_cer(cer_uri, ta_cer_fn)
                else
                    Rsync.fetch_ta_cer(cer_uri, ta_cer_fn)
                end
            else
                @warn "TA certificate for $(talname) not locally available and not fetching
                in this run. Consider passing `fetch_data=true`."
                continue
            end
        end
        #TODO move ta_cer to non-tmp dir!
        =#
        work() = try 
            @info "Processing $(talname)"
            process_ta(ta_fn, root_rf)
            @info "Done processing $(talname)"
        catch e
            @error ta_fn e
            if e isa InterruptException
                put!(results, ErrorException("Processing $(talname) timed out"))
            else
                put!(results, ErrorException("Failed to process $(talname), $(e)"))
            end
        end
        task = Task(work)
        push!(tasks, task)
        schedule(task)

    end

    status = timedwait(() -> all(istaskdone, tasks), 180)
    if status == :timed_out
        @warn "One or more tasks timed out"
        for t_to in filter(t->!istaskdone(t), tasks)
            schedule(t_to, InterruptException(); error=true)
        end
    end
    #processed = 0
    #while isready(results)
    #    res = take!(results)
    #    if res isa ErrorException 
    #        @warn res.msg
    #    else
    #        (rir_root, lkup) = res
    #        add(rpki_root, rir_root)
    #        processed += 1
    #        @info "TAL $(processed)/$(length(tals)) merged: $(rir_root)"
    #    end
    #end
    @info "Done!"
    root_rf
end
=#

##############################
# end of refactor
##############################


#=



"""
    check_ASN1

Validate ASN1 structure of an [`RPKIObject`](@ref). Method definitions in [CER.jl](@ref) etc.
"""
function check_ASN1 end
function check_cert end
function check_resources end

include("CER.jl")
include("MFT.jl")
include("ROA.jl")
include("CRL.jl")

function add(p::RPKINode, c::RPKINode)#, o::RPKIObject)
    c.parent = p
    p.remark_counts_children += c.remark_counts_me + c.remark_counts_children
    if isnothing(p.children)
        p.children = [c]
    else
        push!(p.children, c)
        #if length(Set(p.children)) < length(p.children)
        #    @warn "duplicates in RPKINode children"
        #    throw("stop")
        #end
    end
end
function add(p::RPKINode, c::Vector{RPKINode})
    for child in c
        add(p, child)
    end
end

function add_sibling(a::RPKINode, b::RPKINode)
    if isnothing(a.siblings)
        a.siblings = RPKINode[b]
    else
        push!(a.siblings, b)
    end
    if isnothing(b.siblings)
        b.siblings = RPKINode[a]
    else
        push!(b.siblings, a)
    end
end

function check(::RPKIObject{T}) where {T}
    @warn "unknown RPKIObject type $(T)"
end


function add_roa!(lookup::Lookup, roanode::RPKINode)
    # TODO do we also want to add CERs here?
    @assert roanode.obj isa RPKIObject{ROA}
    roa = roanode.obj.object
    asn = AutSysNum(roa.asid)
    if asn in keys(lookup.ASNs)
        push!(lookup.ASNs[asn], roanode) 
    else
        lookup.ASNs[asn] = [roanode]
    end
end

function process_roa(roa_fn::String, lookup::Lookup, tpi::TmpParseInfo, parent_cer::Union{Nothing, RPKINode}=nothing) :: RPKINode
    roa_obj::RPKIObject{ROA} = check_ASN1(RPKIObject{ROA}(roa_fn), tpi, parent_cer.obj)
    roa_node = RPKINode(roa_obj)
    add_filename!(lookup, roa_fn, roa_node)

    # add EE resources to Lookup
    for r in roa_obj.object.resources_v4
        add_resource(lookup, r.first, r.last, roa_node)
    end
    for r in roa_obj.object.resources_v6
        add_resource(lookup, r.first, r.last, roa_node)
    end

    # add VRPs to Lookup
    for r in roa_obj.object.vrp_tree.resources_v4
        add_resource(lookup, r.first, r.last, roa_node)
    end
    for r in roa_obj.object.vrp_tree.resources_v6
        add_resource(lookup, r.first, r.last, roa_node)
    end
    

    roa_node.remark_counts_me = count_remarks(roa_obj)

    @assert !isnothing(tpi.eeCert)
    check_cert(roa_obj, tpi, parent_cer)
    check_resources(roa_obj, tpi, parent_cer)

    # optionally strip the tree to save memory
    if tpi.stripTree
        roa_obj.tree = nothing
    end
    roa_node
end

struct LoopError <: Exception 
    file1::String
    file2::String
end
LoopError(file1::String) = LoopError(file1, "")
Base.showerror(io::IO, e::LoopError) = print(io, "loop between ", e.file1, " and ", e.file2)

function process_crl(crl_fn::String, lookup::Lookup, tpi::TmpParseInfo, parent_cer::Union{Nothing, RPKINode}=nothing) ::RPKINode
    crl_obj::RPKIObject{CRL} = check_ASN1(RPKIObject{CRL}(crl_fn), tpi, parent_cer.obj)
    check_cert(crl_obj, tpi, parent_cer)
    crl_node = RPKINode(crl_obj)
    add_filename!(lookup, crl_fn, crl_node)
    crl_node.remark_counts_me = count_remarks(crl_obj)
    if tpi.stripTree
        crl_obj.tree = nothing
    end
    crl_node
end

function process_mft(mft_fn::String, lookup::Lookup, tpi::TmpParseInfo, cer_node::RPKINode) :: RPKINode
    mft_dir = dirname(mft_fn)
    tpi.cwd = mft_dir
    mft_obj::RPKIObject{MFT} = try 
        check_ASN1(RPKIObject{MFT}(mft_fn), tpi, cer_node.obj)
    catch e 
        showerror(stderr, e, catch_backtrace())
        @error "MFT: error with $(mft_fn)"
        return RPKINode()
    end
	crl_count = 0

    check_cert(mft_obj, tpi, cer_node)

    mft_node = RPKINode(mft_obj)
    add(cer_node, mft_node)
    # we add the remarks_counts for the mft_obj after we actually processed the
    # fileList on the manifest, as more remarks might be added there
    if tpi.stripTree
        mft_obj.tree = nothing 
    end

    cer_tasks = Vector{Task}()
    cer_results = Channel()

    sub_cers_todo = 0

    for f in mft_obj.object.files
        if !isfile(joinpath(mft_dir, f))
            @warn "[$(get_pubpoint(cer_node))] Missing file: $(f)"
            Mft.add_missing_file(mft_obj.object, f)
            add_missing_filename!(lookup, joinpath(mft_dir, f), mft_node)
            remark_missingFile!(mft_obj, "Listed in manifest but missing on file system: $(f)")
            continue
        end
        if endswith(f, r"\.cer"i)
            # TODO accomodate for BGPsec router certificates
            subcer_fn = joinpath(mft_dir, f)
            try
                # TODO
                # can .cer and .roa files be in the same dir / on the same level
                # of a manifest? in other words, can we be sure that if we reach
                # this part of the `if ext ==`, there will be no other files to
                # check?

                #if subcer_fn in keys(lookup.filenames)
                #    @warn "$(subcer_fn) already seen, loop?"
                #    throw("possible loop in $(subcer_fn)" )
                #end
                #@debug "process_cer from _mft for $(basename(subcer_fn))"
                
                #FIXME far too expensive..
                #tpi_copy = deepcopy(tpi)
                #@async put!(cer_tasks, process_cer(subcer_fn, lookup, tpi_copy))
                #work() =  put!(cer_results, process_cer(subcer_fn, lookup, tpi_copy))
                #t = Task(work)
                #push!(cer_tasks, t)
                #schedule(t)

                sub_cer_node = process_cer(subcer_fn, lookup, tpi, mft_node)
                add(mft_node, sub_cer_node)
                
            catch e
                if e isa LoopError
                    #@warn "LoopError, trying to continue"
                    #@warn "but pushing $(basename(subcer_fn))"

                    if isnothing(mft_obj.object.loops)
                        mft_obj.object.loops = [basename(subcer_fn)]
                    else
                        push!(mft_obj.object.loops, basename(subcer_fn))
                    end
                    remark_loopIssue!(mft_obj, "Loop detected with $(basename(subcer_fn))")
                    #@warn "so now it is $(m.object.loops)"
                else
                    #throw("MFT->.cer: error with $(subcer_fn): \n $(e)")
                    rethrow(e)
                    #showerror(stderr, e, catch_backtrace())
                end
            end
        elseif endswith(f, r"\.roa"i)
            roa_fn = joinpath(mft_dir, f)
            try
                roa_node = process_roa(roa_fn, lookup, tpi, cer_node)
                add(mft_node, roa_node)
                add_roa!(lookup, roa_node)
            catch e
                #showerror(stderr, e, catch_backtrace())
                #throw("MFT->.roa: error with $(roa_fn): \n $(e)")
                rethrow(e)
            end
        elseif endswith(f, r"\.crl"i)
            crl_fn = joinpath(mft_dir, f)
            crl_count += 1
            if crl_count > 1
                @error "more than one CRL on $(mft_fn)"
                remark_manifestIssue!(mft_obj, "More than one CRL on this manifest")
            end
            try
                crl_node = process_crl(crl_fn, lookup, tpi, cer_node)
                add(mft_node, crl_node)
                add_sibling(cer_node, crl_node)
            catch e
                rethrow(e)
            end
        end

    end

    #=
    # processing the @async'ed sub_cers
    @debug "pre while, sub_cers_todo: $(sub_cers_todo)"
    no_of_subcers = 0
    #while !all(istaskdone, cer_tasks)
    while (sub_cers_todo > no_of_subcers)
        #@debug "in while, not all subcertasks done"
        #while isready(cer_results)
            sub_cer_node = take!(cer_results)
            @debug "adding sub_cer $(sub_cer_node) to mft $(mft_node)"
            add(mft_node, sub_cer_node)
            no_of_subcers += 1
        #end
    end
    @debug "sub_cers done, $(no_of_subcers) processed for $(mft_node)"
    =#



    # returning:
    mft_node.remark_counts_me = count_remarks(mft_obj) 
    add_filename!(lookup, mft_fn, mft_node)
    mft_node
end

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

function process_cer(cer_fn::String, lookup::Lookup, tpi::TmpParseInfo, parent_mft::Union{Nothing, RPKINode}=nothing) :: RPKINode
    # now, for each .cer, get the CA Repo and 'sync' again
    if cer_fn in keys(lookup.filenames)
        @warn "$(basename(cer_fn)) already seen, loop?"
        throw(LoopError(cer_fn))
    else
        # placeholder: we need to put something in because when a loop appears
        # in the RPKI repo, this call will never finish so adding it at the end
        # of this function will never happen.
        add_filename!(lookup, cer_fn, RPKINode())
    end

    parent_cer = if isnothing(parent_mft)
        nothing
    else
        parent_mft.parent
    end
    cer_obj::RPKIObject{CER} = check_ASN1(RPKIObject{CER}(cer_fn), tpi, parent_cer)

    if !isnothing(tpi.tal)
        if cer_obj.object.rsa_modulus != tpi.tal.key
            remark_validityIssue!(cer_obj, "key does not match TAL")
            @error "Certificate key does not match key in TAL: $(cer_fn)"
        end
        tpi.tal = nothing
    end

    cer_node = RPKINode(cer_obj)
    if !isnothing(parent_mft)
        #@debug "add: $(parent_mft.parent.obj.filename) , $(cer_node.obj.filename)"
        add(parent_mft, cer_node)
    end

    #@debug "pre check_resources: typeof parent_mft: $(typeof(parent_mft))"
    #@debug cer_node.obj.object isa CER && parent_cer.obj.object isa CER

    #push!(tpi.certStack, cer_obj.object)
    check_cert(cer_obj, tpi, parent_cer)
    check_resources(cer_obj, tpi, parent_cer)

    mft_host, mft_path = split_scheme_uri(cer_obj.object.manifest)
    mft_fn = joinpath(tpi.data_dir, mft_host, mft_path)

    if cer_obj.sig_valid 
        push!(lookup.valid_certs, cer_node)
    else
        push!(lookup.invalid_certs, cer_node)
    end

    for r in cer_obj.object.resources_v4
        add_resource(lookup, r.first, r.last, cer_node)
    end
    for r in cer_obj.object.resources_v6
        add_resource(lookup, r.first, r.last, cer_node)
    end

    (ca_host, ca_path) = if tpi.transport == rsync
        split_scheme_uri(cer_obj.object.pubpoint)
    elseif tpi.transport == rrdp
        if !isempty(cer_obj.object.rrdp_notify)
            split_scheme_uri(cer_obj.object.rrdp_notify)
        else
            @warn "No RRDP SIA for $(cer_fn), rsync SIA is $(cer_obj.object.pubpoint)"
            #(nothing, nothing)
            #pop!(tpi.certStack)
            return cer_node
        end
    end

    
    rsync_module = joinpath(ca_host, splitpath(ca_path)[1])
    #depth = length(tpi.certStack)
    depth = 1
    if tpi.transport == rrdp && !(ca_host in keys(lookup.pubpoints)) ||
        tpi.transport == rsync && !(rsync_module in keys(lookup.rsync_modules))
        lookup.pubpoints[ca_host] = depth => Set(cer_node)
        if tpi.fetch_data
            if tpi.transport == rsync
                @debug "rsync, $(rsync_module) not seen before"
                Rsync.fetch_all(ca_host, ca_path)
                lookup.rsync_modules[rsync_module] = cer_fn
            elseif tpi.transport == rrdp
                rrdp_update = RRDP.fetch_process_notification(cer_node)
                RRDP.add(lookup, rrdp_update)
            end
        end
    else
        (d, s) = lookup.pubpoints[ca_host]
        if depth < d
            @debug "existing pubpoint $(ca_host) at lower degree $(depth) instead of $(d)"
            lookup.pubpoints[ca_host] = depth => Set(cer_node)
        elseif depth == d
            #@debug "existing pubpoint $(ca_host) at similar depth $(depth)"
            #(_, set) = lookup.pubpoints[ca_host] 
            push!(s, cer_node)
        end
    end

    if tpi.stripTree
        cer_obj.tree = nothing
    end

    #TODO: should we still process through the directory, even though there was
    #no manifest?
    if !isfile(mft_fn)
        @error "[$(get_pubpoint(cer_node))] manifest $(basename(mft_fn)) not found"
        add_missing_filename!(lookup, mft_fn, cer_node)
        remark_missingFile!(cer_obj, "Manifest file $(basename(mft_fn)) not in repo")
    else

        try
            mft = process_mft(mft_fn, lookup, tpi, cer_node)
            #add(cer_node, mft)
        catch e
            if e isa LoopError
                @warn "Loop! between $(basename(e.file1)) and $(basename(e.file2))"
            else
                rethrow(e)
            end
        end
    end

    # we already counted the remarks from .tree, now add those from the object:
    cer_node.remark_counts_me = count_remarks(cer_obj)

    add_filename!(lookup, cer_fn, cer_node)
    #pop!(tpi.certStack)
    cer_node
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
function process_ta(ta_cer_fn::String; tal=nothing, lookup=Lookup(), tpi_args...) :: Tuple{RPKINode, Lookup}
    @debug "process_ta for $(basename(ta_cer_fn))"
    if haskey(tpi_args, :data_dir)
        @debug "using custom data_dir $(data_dir)"
    end
    @assert isfile(ta_cer_fn) "Can not open file $(ta_cer_fn)"

    tpi = TmpParseInfo(;lookup, tal, tpi_args...)

    if !isdir(tpi.data_dir)
        if !tpi.fetch_data 
            @error "Can not find directory $(tpi.data_dir) and not creating/fetching anything"
            throw("invalid configuration")
        end
    end


    # get rsync url from tal
    #
    rir_root = RPKINode()
    try
        rir_root = process_cer(ta_cer_fn, lookup, tpi)
    catch e
        @error "error while processing $(ta_cer_fn)"
        @error e
        display(stacktrace(catch_backtrace()))
        rethrow(e)
    end

    # 'fetch' cer from TAL ?
    # check TA signature (new)
    # process first cer, using data_dir
    @debug "process_ta done, returning tuple"
    return rir_root, lookup
end

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
function process_tas(tals=CFG["rpki"]["tals"]; tpi_args...) :: Union{Nothing, Tuple{RPKINode, Lookup}}
    if isempty(tals)
        @warn "No TALs configured, please create/edit JDR.toml and run

            JDR.Config.generate_config()

        "
        return nothing
    end

    _tpi = TmpParseInfo(; tpi_args...)

    if _tpi.fetch_data
        if !isdir(_tpi.data_dir)
            @info "Configured data directory $(_tpi.data_dir) does not exist, will try to create it"
            try
                mkpath(_tpi.data_dir)
            catch e
                @warn "Failed to create $(_tpi.data_dir): ", e
            end
        else
            # we fetch full snapshots for RRDP, so we start with a clean slate every fetch
            # for rsync we want to keep the old dir around to reduce transfer delays
            #if _tpi.transport == rrdp
            #    @info "Configured RRDP data directory exists, moving it to .prev"
            #    try
            #        dir = _tpi.data_dir
            #        if isdirpath(dir)
            #            # contains trailing slash, chop it off
            #            dir = dirname(dir)
            #        end

            #        mv(dir, dir*".prev"; force=true)
            #    catch e
            #        @warn "Failed to move $(dir) to $(dir).prev : ", e
            #    end
            #end
        end
    end

    lookup = Lookup()
    rpki_root = RPKINode()
    rpki_root.obj = RPKIObject{RootCER}()

    tasks = Vector{Task}()
    results = Channel(10)

    for (talname, tal_fn) in tals
        @debug "for talname: $(talname)"
        tal = parse_tal(joinpath(CFG["rpki"]["tal_dir"], tal_fn))
        cer_uri = if _tpi.transport == rsync
            tal.rsync
        elseif _tpi.transport == rrdp
            if isnothing(tal.rrdp)
                @warn "No RRDP URI for tal $(talname), skipping"
                continue
            end
            tal.rrdp
        end

        (hostname, cer_fn) = split_scheme_uri(cer_uri) 
        ta_cer_fn = joinpath(_tpi.data_dir, "tmp", hostname, cer_fn)
        if !isfile(ta_cer_fn)
            if _tpi.fetch_data
                if _tpi.transport == rrdp
                    RRDP.fetch_ta_cer(cer_uri, ta_cer_fn)
                else
                    Rsync.fetch_ta_cer(cer_uri, ta_cer_fn)
                end
            else
                @warn "TA certificate for $(talname) not locally available and not fetching
                in this run. Consider passing `fetch_data=true`."
                continue
            end
        end
        #TODO move ta_cer to non-tmp dir!

        work() = try 
            @info "Processing $(talname)"
            put!(results, process_ta(ta_cer_fn; lookup, tal, tpi_args...))
            @info "Done processing $(talname)"
        catch e
            @error ta_cer_fn e
            if e isa InterruptException
                put!(results, ErrorException("Processing $(talname) timed out"))
            else
                put!(results, ErrorException("Failed to process $(talname), $(e)"))
            end
        end
        task = Task(work)
        push!(tasks, task)
        schedule(task)

    end

    status = timedwait(() -> all(istaskdone, tasks), 180)
    if status == :timed_out
        @warn "One or more tasks timed out"
        for t_to in filter(t->!istaskdone(t), tasks)
            schedule(t_to, InterruptException(); error=true)
        end
    end
    processed = 0
    while isready(results)
        res = take!(results)
        if res isa ErrorException 
            @warn res.msg
        else
            (rir_root, lkup) = res
            add(rpki_root, rir_root)
            processed += 1
            @info "TAL $(processed)/$(length(tals)) merged: $(rir_root)"
        end
    end
    @info "Done, $(processed)/$(length(tals)) merged successfully"

    rpki_root, lookup
end

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
