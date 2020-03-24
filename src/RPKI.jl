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

function process_roa(roa_fn::String)
    o::RPKIObject{ROA} = check(RPKIObject(roa_fn))
end

function process_mft(mft_fn::String)
    m::RPKIObject{MFT} = try 
        check(RPKIObject(mft_fn))
    catch e 
        #showerror(stderr, e, catch_backtrace())
        @error "MFT: error with $(mft_fn)"
        return
    end
    #@debug m.filename
    mft_dir = dirname(mft_fn)
    for f in m.object.files
        # check for .cer
        ext = splitext(f)[2] 
        if ext == ".cer"
            subcer_fn = joinpath(mft_dir, f)
            @assert isfile(subcer_fn)
            try
                process_cer(subcer_fn)
            catch e
                throw("MFT->.cer: error with $(subcer_fn): \n $(e)")
            end
        elseif ext == ".roa"
            roa_fn = joinpath(mft_dir, f)
            try
                process_roa(roa_fn)
            catch e
                #showerror(stderr, e, catch_backtrace())
                throw("MFT->.roa: error with $(roa_fn): \n $(e)")
            end
        end

    end

end

function process_cer(cer_fn::String)
    #@debug cer_fn
    # now, for each .cer, get the CA Repo and 'sync' again
    o::RPKIObject{CER} = check(RPKIObject(cer_fn))

    (ca_host, ca_path) = split_rsync_url(o.object.pubpoint)
    ca_dir = joinpath(REPO_DIR, ca_host, ca_path)
    @assert isdir(ca_dir)

    mft_host, mft_path = split_rsync_url(o.object.manifest)
    mft_fn = joinpath(REPO_DIR, mft_host, mft_path)
    #@assert isfile(mft_fn)
    if !isfile(mft_fn)
        @error "manifest $(basename(mft_fn)) not found"
        return
    end
    #@debug mft_fn
    #m = nothing
    
    process_mft(mft_fn)

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
        try
            process_cer(ta_cer)
        catch e
            # TODO: what is a proper way to record the error, but continue with
            # the rest of the repo?
            # maybe a 'hard error counter' per RIR/pubpoint ?
            # also revisit the try/catches in process_cer()
            #showerror(stderr, e, catch_backtrace())
            @error "error while processing $(ta_cer)"
            @error e
            #showerror(stderr, e, catch_backtrace())
            #break
        end
        
    end
end

end # module
