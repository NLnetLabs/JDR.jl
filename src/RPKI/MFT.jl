module Mft
using JDR.ASN1: ASN1, check_tag, childcount, to_bigint, check_contextspecific, check_OID
using JDR.Common: @oid, remark_ASN1Error!, remark_manifestIssue!, remark_validityIssue!, remark_missingFile!
using JDR.RPKI: MFT, get_pubpoint
#using JDR.RPKICommon: RPKINode, RPKIObject, RPKIFile, CER, TmpParseInfo, get_object
#using JDR.PKIX.CMS: check_ASN1_contentType, check_ASN1_content # from macros

using Dates: DateTime, @dateformat_str
using SHA: sha256

import JDR.RPKI # to extend check_ASN1, check_cert
include("../ASN1/macro_check.jl")


function Base.show(io::IO, mft::MFT)
    print(io, "  num of files: ", length(mft.files), '\n')
    if !isnothing(mft.missing_files)
        printstyled(io, "  missing files: \n")
        for m in mft.missing_files
            print(io, "    ", m, '\n')
        end
    end
    print(io, "  thisUpdate: ", mft.this_update, '\n')
    print(io, "  nextUpdate: ", mft.next_update, '\n')
end

function add_missing_file(m::MFT, filename::String)
    if isnothing(m.missing_files)
        m.missing_files = [filename]
    else
        push!(m.missing_files, filename)
    end
end

function gentime_to_ts(raw::Vector{UInt8})
    DateTime(String(copy(raw)), dateformat"yyyymmddHHMMSSZ")
end

import Base.length
length(::Nothing) = 0 #used in childcount from validation_common.jl

@check "version" begin
    check_contextspecific(node, 0x00)
    # EXPLICIT tagging, so the version node be in a child
    childcount(node, 1)
    check_tag(node[1], ASN1.INTEGER)
    if ASN1.value(node[1].tag) == 0
        #info!(node[1], "version explicitly set to 0 while that is the default")
    end
end

@check "manifestNumber" begin
    check_tag(node, ASN1.INTEGER)
end

@check "thisUpdate" begin
    check_tag(node, ASN1.GENTIME)
    try
        rf.object.this_update = (@__MODULE__).gentime_to_ts(node.tag.value)
    catch e
        if e isa ArgumentError
            remark_ASN1Error!(rf, "Could not parase GENTIME in thisUpdate field")
        else
            @error e
        end
    end
end
@check "nextUpdate" begin
    check_tag(node, ASN1.GENTIME)
    try
        rf.object.next_update = (@__MODULE__).gentime_to_ts(node.tag.value)
    catch e
        if e isa ArgumentError
            remark_ASN1Error!(rf, "Could not parase GENTIME in nextUpdate field")
        else
            @error e
        end
    end
end

@check "fileHashAlg" begin
    check_OID(node, @oid "2.16.840.1.101.3.4.2.1")
end

@check "fileList" begin
    check_tag(node, ASN1.SEQUENCE)
    cwd = dirname(rf.filename)
    for file_and_hash in node.children
        check_tag(file_and_hash, ASN1.SEQUENCE)
        check_tag(file_and_hash[1], ASN1.IA5STRING)
        check_tag(file_and_hash[2], ASN1.BITSTRING)

        filename = ASN1.value(file_and_hash[1].tag)

        full_fn = joinpath(cwd, filename)
        if isfile(full_fn)
            push!(rf.object.files, filename)
            open(full_fn) do fh
                local_hash = sha256(fh)
                if file_and_hash[2].tag.len != 33
                    @warn "illegal file hash length in $(rf.filename) for filename $(filename)"
                    remark_ASN1Error!(file_and_hash[2], "Expecting length of 33")
                elseif local_hash != file_and_hash[2].tag.value[end-31:end]
                    @warn "invalid hash for", full_fn
                    remark_manifestIssue!(rf, "Invalid hash for $(filename)")
                end
            end
        else
            @warn "[$(get_pubpoint(rf.parent))] Missing file: $(full_fn)"
            if isnothing(rf.object.missing_files)
                rf.object.missing_files = String[filename]
            else
                push!(rf.object.missing_files, filename)
            end
            remark_missingFile!(rf, "Listed in manifest but missing on file system: $(filename)")
        end
    end
end

@check "manifest" begin
    # Manifest ::= SEQUENCE {
    #  version     [0] INTEGER DEFAULT 0,
    #  manifestNumber  INTEGER (0..MAX),
    #  thisUpdate      GeneralizedTime,
    #  nextUpdate      GeneralizedTime,
    #  fileHashAlg     OBJECT IDENTIFIER,
    #  fileList        SEQUENCE SIZE (0..MAX) OF FileAndHash
    #  }
    check_tag(node, ASN1.SEQUENCE)
    childcount(node, 5:6)
    # the 'version' is optional, defaults to 0
    offset = 0
    if length(node.children) == 6
        (@__MODULE__).check_ASN1_version(rf, node[1], gpi, tpi)
        offset += 1
	end
    (@__MODULE__).check_ASN1_manifestNumber(rf, node[offset+1], gpi, tpi)
    (@__MODULE__).check_ASN1_thisUpdate(rf, node[offset+2], gpi, tpi)
    (@__MODULE__).check_ASN1_nextUpdate(rf, node[offset+3], gpi, tpi)
    (@__MODULE__).check_ASN1_fileHashAlg(rf, node[offset+4], gpi, tpi)
    (@__MODULE__).check_ASN1_fileList(rf, node[offset+5], gpi, tpi)
end

#function RPKI.check_ASN1(o::RPKIObject{MFT}, tpi::TmpParseInfo, parent_cer::Union{Nothing, RPKIObject{CER}}=nothing) :: RPKIObject{MFT}
#    cmsobject = o.tree
#    # CMS, RFC5652:
#    #       ContentInfo ::= SEQUENCE {
#    #           contentType ContentType,
#    #           content [0] EXPLICIT ANY DEFINED BY contentType }
#    
#    check_tag(cmsobject, ASN1.SEQUENCE)
#    childcount(cmsobject, 2)
#
#    # from CMS.jl:
#    check_ASN1_contentType(o, cmsobject[1], tpi)
#    check_ASN1_content(o, cmsobject[2], tpi, parent_cer)
#
#    check_ASN1_manifest(o, tpi.eContent, tpi)
#
#    o
#end

#function RPKI.check_cert(o::RPKIObject{MFT}, tpi::TmpParseInfo, parent_cer::RPKINode)
#    # hash tpi.eeCert
#    @assert !isnothing(tpi.eeCert)
#    tbs_raw = @view o.tree.buf.data[tpi.eeCert.tag.offset_in_file:tpi.eeCert.tag.offset_in_file + tpi.eeCert.tag.len + 4 - 1]
#    my_hash = bytes2hex(sha256(tbs_raw))
#
#    # decrypt tpi.eeSig 
#    #v = powermod(to_bigint(@view tpi.eeSig.tag.value[2:end]), tpi.certStack[end].rsa_exp,tpi.certStack[end].rsa_modulus)
#    v = powermod(to_bigint(@view tpi.eeSig.tag.value[2:end]), get_object(parent_cer).rsa_exp, get_object(parent_cer).rsa_modulus)
#    v.size = 4
#    v_str = string(v, base=16, pad=64)
#    
#    # compare hashes
#    if v_str == my_hash
#        o.sig_valid = true
#    else
#        @error "invalid signature for" o.filename
#        remark_validityIssue!(o, "invalid signature")
#        o.sig_valid = false
#    end
#
#    # compare subject with SKI
#    # TODO
#end

end
