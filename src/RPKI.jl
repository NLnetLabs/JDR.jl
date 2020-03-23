module RPKI
using ..ASN
using ..DER
using IPNets


export retrieve_all

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


# Retrieving and validating the entire repository 

# start at the RIR TAs
TAL_URLS = Dict(
    :afrinic    => "rsync://rpki.afrinic.net/repository/AfriNIC.cer",
    :apnic      => "rsync://rpki.apnic.net/repository/apnic-rpki-root-iana-origin.cer",
    :arin       => "rsync://rpki.arin.net/repository/arin-rpki-ta.cer",
    :lacnic     => "rsync://repository.lacnic.net/rpki/lacnic/rta-lacnic-rpki.cer",
    :ripe       => "rsync://rpki.ripe.net/ta/ripe-ncc-ta.cer"
)
REPO_DIR = joinpath(homedir(), ".rpki-cache/repository/rsync")

function split_rsync_url(url::String) :: Tuple{String, String}
    m = match(r"rsync://([^/]+)/(.*)", url)
    (hostname, cer_fn) = m.captures
    (hostname, cer_fn)
end

function process_cer(cer_fn::String)
    @debug cer_fn
    # now, for each .cer, get the CA Repo and 'sync' again
    o::RPKIObject{CER} = check(RPKIObject(cer_fn))

    (ca_host, ca_path) = split_rsync_url(o.object.pubpoint)
    ca_dir = joinpath(REPO_DIR, ca_host, ca_path)
    @assert isdir(ca_dir)

    mft_host, mft_path = split_rsync_url(o.object.manifest)
    mft_fn = joinpath(REPO_DIR, mft_host, mft_path)
    mft_dir = dirname(mft_fn)
    @assert isfile(mft_fn)
    m::RPKIObject{MFT} = check(RPKIObject(mft_fn))

    @debug m.filename
    for f in m.object.files
        # check for .cer
        if splitext(f)[2] == ".cer"
            subcer_fn = joinpath(mft_dir, f)
            @assert isfile(subcer_fn)
            process_cer(subcer_fn)
        end

    end

    # TODO check RFC on directory structures: do the .mft and .cer have to
    # reside in the same dir?
end

function retrieve_all()
    for (rir, rsync_url) in TAL_URLS
        @debug rir
        (hostname, cer_fn) = split_rsync_url(rsync_url)  
        rir_dir = joinpath(REPO_DIR, hostname)

        # For now, we rely on Routinator for the actual fetching
        # We do however construct all the paths and mimic the entire procedure
        @assert isdir(rir_dir)

        # 'rsync' the .cer from the TAL
        ta_cer = joinpath(rir_dir, cer_fn)
        @assert isfile(ta_cer)

        # start recursing
        process_cer(ta_cer)
        
    end
end

end # module
