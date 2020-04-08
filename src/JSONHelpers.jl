JSON2.@format RPKI.RPKINode begin
        parent => (;exclude=true,)
end

JSON2.@format RPKI.RPKIObject{T} where T begin
        tree => (;exclude=true,)
end

# custom view for RPKIObject{T}
# includes the tree, but does not link to parent or children
# howto: https://github.com/quinnj/JSON2.jl/issues/12
struct ObjectDetails{T}
    filename::String
    tree::RPKI.Node
    object::T
    objecttype::String
    remarks::Union{Nothing, Vector{RPKI.Remark}}
end

function ObjectDetails(r::RPKI.RPKIObject) 
    # we parse this again, because it is removed from the main tree/lookup 
    tree = DER.parse_file_recursive(r.filename)
    ObjectDetails(r.filename,
                  tree,
                  r.object,
                  string(nameof(typeof(r.object))),
                  r.remarks
                )
end

struct Basename
    filename::String
end
JSON2.@format ObjectDetails begin
    filename => (; jsontype=Basename,)
end
JSON2.write(io::IO, bn::Basename) = JSON2.write(io, basename(bn.filename))
Base.convert(Basename, s) = Basename(s)

function JSON2.write(io::IO, t::ASN.Tag{T}) where {T}
    JSON2.write(io, "$(nameof(ASN.tagtype(t))) ($(t.len))")
    #JSON2.write(io, " ($(t.len))")
end


# Slim copy of RPKI.CER, with empty prefixes and ASNs Vectors
struct SlimCER 
    pubpoint::String
    manifest::String
    rrdp_notify::String
    inherit_prefixes::Bool
    prefixes::Vector{Union{IPNet, Tuple{IPNet, IPNet}}}
    inherit_ASNs::Bool
    ASNs::Vector{Union{Tuple{UInt32, UInt32}, UInt32}}
end
SlimCER(cer::RPKI.CER) = SlimCER(cer.pubpoint, cer.manifest, cer.rrdp_notify, cer.inherit_prefixes, [], cer.inherit_ASNs, [])
JSON2.@format SlimCER begin
    prefixes => (;exclude=true,)
    ASNs => (;exclude=true,)
end

# Slim copy of RPKI.MFT, with an empty files Vector
struct SlimMFT
    files::Vector{String}
    loops::Union{Nothing, Vector{String}}
    missing_files::Union{Nothing, Vector{String}}
    this_update::Union{Nothing, DateTime}
    next_update::Union{Nothing, DateTime}
end
SlimMFT(mft::RPKI.MFT) = SlimMFT([], mft.loops, mft.missing_files, mft.this_update, mft.next_update)
JSON2.@format SlimMFT begin
    files => (;exclude=true,)
end


to_slim(o::RPKI.MFT) = SlimMFT(o)
to_slim(o::RPKI.CER) = SlimCER(o)
to_slim(o::RPKI.ROA) = o

to_slim(o::RPKI.RPKIObject) = RPKI.RPKIObject(o.filename, o.tree, to_slim(o.object), o.remarks)

# the circular ref between  `parent` and `children` in the RPKINode struct
# causes the JSON generation to stackoverflow
# So we combine to_root() with a custom JSON format where we exclude the parent
# Results are then a chain from root to leaf, though without refs to the parent
# FIXME this comment is outdated/incorrect now
function to_root(node::RPKI.RPKINode) :: Vector
    current = node
    res = Vector{Any}([current.obj])
    while !isnothing(current.parent)
        if !isnothing(current.parent.obj)
            #push!(res, to_slim(current.parent.obj.object))
            push!(res, to_slim(current.parent.obj))
        end
        current = current.parent
    end
    res
end



