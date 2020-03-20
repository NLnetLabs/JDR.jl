module DER
using ..ASN
using Mmap

# Possible/common mistakes or violations:
# - a primitive BITSTRING actually containing other tags (thus being constructed)
# - encapsulating OCTETSTRINGS?
# - no terminating \x0000 in an Indefinite form BITSTRING? in the ripe ta cer this seems to be the
# case. Perhaps they rely on the Length of the root SEQUENCE?

#struct Buf
#    buffer::Array{UInt8, 1}
#    index::UInt64
#    Buf(b) = new(b, 1)
#end
#
#
# TODO
# - try OwnTime.jl for profiling

const STRICT = true

struct Buf
    iob::IOBuffer
end

Buf(b::Array{UInt8,1})  = Buf(IOBuffer(b))
Buf(s::IOStream)        = Buf(IOBuffer(read(s)))
#Buf(s::IOStream)        = Buf(IOBuffer(Mmap.mmap(s, Vector{UInt8})))
#
function lookahead(buf::Buf) :: UInt8
    buf.iob.ptr += 1 
    buf.iob.data[buf.iob.ptr - 1]
end

struct NotImplementedYetError <: Exception
    msg::String
end
NotImplementedYetError() = NotImplementedYetError("something is not yet implemented..")
Base.showerror(io::IO, e::NotImplementedYetError) = print(io, "Not Yet Implemented: ", e.msg)




function next!(buf::Buf) :: Union{Tag{<:AbstractTag}, Nothing}
    _tmp = Vector{UInt8}(undef, 1) 
    #if eof(buf.iob) 
    #    @warn "wat"
    #    return nothing
    #end
    readbytes!(buf.iob, _tmp, 1) 
    #first_byte = read(buf.iob, 1)[1] 
    first_byte = _tmp[1] 
    
    #first_byte = buf.iob.data[buf.iob.ptr]  #FIXME make Buf.lookahead or something
                                            # that also does the ptr++
    #buf.iob.ptr += 1
    #first_byte = lookahead(buf)

    tagclass    = first_byte  >> 6; # bit 8-7
    constructed = first_byte & 0x20 == 0x20 # bit 6
    tagnumber   = first_byte & 0x1f # bit 5-0
    if tagnumber == 31
        longtag = 0
        #readbytes!(buf.iob, _tmp, 1)
        #byte = read(buf.iob, 1)[1]
        #byte =_tmp[1]
        
        #byte = buf.iob.data[buf.iob.ptr]
        #buf.iob.ptr += 1

        byte = lookahead(buf)
        while byte & 0x80 == 0x80 # first bit is 1
            longtag = (longtag << 7) | (byte & 0x7f) # take the last 7 bits
            #byte = read(buf.iob, 1)[1]
            #readbytes!(buf.iob, _tmp, 1)
            #byte = _tmp[1]
            byte = buf.iob.data[buf.iob.ptr]
            buf.iob.ptr += 1
        end
        tagnumber = (longtag << 7) | (byte & 0x7f) # take the last 7 bits
    end
    #if tagclass > 0 # TODO what should we do on a context-specific (0x02) class?
    #    @debug "tagclass", tagclass
    #end

    #readbytes!(buf.iob, _tmp, 1) 
    #lenbyte = Int32(read(buf.iob, 1)[1]) 
    #lenbyte = Int32(_tmp[1])
    lenbyte = buf.iob.data[buf.iob.ptr]
    buf.iob.ptr += 1
    len_indef = lenbyte == 0x80
    len = lenbyte

    if lenbyte & 0x80 == 0x80 && lenbyte != 0x80 
        # first bit set, but not 0x80 (Indefinite form) so we are dealing with either a
        # Definite long
        # Reserved
        
        # Reserved:
        if lenbyte == 0xff
            @warn "Reserved Length in tag?"
            return Tag{InvalidTag}()
        end

        # Definite long
        octets::Array{UInt8,1} = read(buf.iob, lenbyte & 0x7f)
        res::Int64 = 0
        for o in octets
            res = (res << 8) | o
        end
        len = res
    end
    # check for cases where we are parsing something that is not a (valid) tag
    if len < 0
        #@warn "negative length tag $(len) == $(bitstring(len))", tagnumber
        #error("negative length")
        return Tag{InvalidTag}()
    elseif len > (buf.iob.size - buf.iob.ptr + 1) 
        #@warn "length $(len) goes beyond end of buffer $(buf.iob.size) - $(buf.iob.ptr), returning InvalidTag"
        return Tag{InvalidTag}()
    end
    @assert(len >= 0)

    value = if len_indef
        #@warn "indef len, not reading value"
        []
    elseif tagnumber == 16 # FIXME also include SET ?
        #@debug "next! for SEQUENCE, _not_ reading value"
        #[] 
        nothing
    #elseif constructed && tagclass == 0x02
    #    #@debug "here with len $(len)"
    #    read(buf.iob, len) 
    elseif !constructed
        #@debug "primitive $(tagnumber), reading value of len $(len)"
        read(buf.iob, len) 
    else
        #@warn "constructed, def len, NOT reading value, but should we get here?"
        #read(buf.iob, len)
        #[]
        nothing
    end
    return Tag(tagclass, constructed, tagnumber, len, len_indef, value)
end

mutable struct Stack
    level::UInt8
end
push(s::Stack) = s.level += 1
pop(s::Stack) = s.level -= 1
empty(s::Stack) = s.level == 0

function _parse!(tag, buf, indef_stack::Stack, recurse_into_octetstring = false) :: Node
    #@debug (tag, indef_stack, buf.iob.ptr)
    me = Node(tag) 
    if isa(tag, Tag{OCTETSTRING})
        if tag.constructed
            #TODO what about constructed BITSTRINGs, are those allowed?
            remark!(me, "constructed OCTETSTRING, not allowed in DER")
        end
    end
    if tag.len_indef
        remark!(me, "indefinite length, not allowed in DER")
    end
    #if tag isa Tag{CONTEXT_SPECIFIC} && tag.constructed && ! tag.len_indef
    #    @debug "got a constructed CONTEXT_SPECIFIC of definite length $(tag.len)"
    #end

    if isa(tag, Tag{SEQUENCE}) || isa(tag, Tag{SET}) ||
        ((isa(tag, Tag{CONTEXT_SPECIFIC}) ||
          isa(tag, Tag{OCTETSTRING}) || isa(tag, Tag{BITSTRING})) && tag.constructed )#&& !(tag.class == 0x02))
        if tag.len_indef 
            my_indef_stack_level = indef_stack.level
            push(indef_stack)
            while !empty(indef_stack)
                #@debug "inner $(indef_stack) > $(my_indef_stack_level)?"
                subtag = DER.next!(buf)
                if !(isa(subtag, Tag{Unimplemented}) || isa(subtag, Tag{InvalidTag}))
                    if isa(subtag, Tag{RESERVED_ENC}) && subtag.len == 0
                        pop(indef_stack)
                        break
                    else
                        ASN.append!(me, _parse!(subtag, buf, indef_stack))
                    end
                else
                    pop(indef_stack)
                end
            end
        else
            #@debug "def len, whiling inside", tag
            offset = buf.iob.ptr
            tmp_protect = 0
            #@debug "buf.iob.ptr $(buf.iob.ptr) , offset+tag.len $(offset+tag.len)"
            while buf.iob.ptr < offset+tag.len && tmp_protect < 99999  
                #@debug "in while at $(buf.iob.ptr) / $(offset+tag.len)"
                subtag = DER.next!(buf)
                #@debug "got subtag", subtag
                if subtag isa Tag{RESERVED_ENC} && subtag.len == 0
                    pop(indef_stack)
                    #@debug "double NULL in lower while, -- == $(indef_stack)"
                    break
                elseif !(isa(subtag, Tag{Unimplemented}) || isa(subtag, Tag{InvalidTag}))
                    #@debug "in lower while, appending subtag $(subtag) to $(me)"
                    #@debug "my value is $(me.tag.value)"
                    ASN.append!(me, _parse!(subtag, buf, indef_stack))
                else
                    #@debug "got Unimplemented at $(buf.iob.ptr), tagnumber | tagclass:", subtag.number | subtag.class
                    #buf.iob.ptr -= 1
                    #dbg = read(buf.iob, max_read) 
                    #@debug "discarding", dbg
                end
                tmp_protect += 1
                #@debug "end while at $(buf.iob.ptr) / $(offset+tag.len)"
            end
            if tmp_protect > 99990
                @warn "high tmp_protect"
                error("protection mechanism kicked in")
            end
            #@debug "post while, tmp_protect $(tmp_protect)"
        end
    #elseif isa(tag, Tag{BITSTRING})
    #    #@debug "in BITSTRING of len", tag.len
    #    #dbg = read(buf.iob, 2)
    #    #buf.iob.ptr -= 2
    #    #@debug "first 2 bytes of BITSTRING:", dbg
    #    skip_unused_octet = 0
    #    if tag.class != 0x02
    #        @warn "tag.class is not 0x02 .."
    #        skip_unused_octet = 1
    #    else
    #        @warn "tag.class is 0x02 .."
    #    end
    #    #if tag.len > 2 && tag.value[1 + skip_unused_octet] == 0x30 
    #    lookahead = read(buf.iob, 1+ skip_unused_octet)[end]
    #    buf.iob.ptr -= 1 # TODO -= 1 or 1+skip_unused_octet ? 
    #    @debug "lookahead", lookahead
    #    if tag.len > 2 && lookahead == 0x30 
    #        # nested SEQUENCE in this BITSTRING
    #        #subbuf = DER.Buf(tag.value[1 + skip_unused_octet:end])
    #        subtag = DER.next!(buf)
    #        @debug "calling _parse! for subtag of BITSTRING, max_read:", tag.len
    #        ASN.append!(me, _parse!(subtag, buf, tag.len))
    #    else
    #        @debug "no SEQUENCE in this BITSTRING, filling .value"
    #        tag.value = read(buf.iob, tag.len)
    #    end
    elseif recurse_into_octetstring && isa(tag, Tag{OCTETSTRING})
        #FIXME with the specific objects checks in RPKI.jl we can probably
        #remove this altogether
        @debug "recursing into octetstring"
        throw("recursing into octetstring from DER.jl")
        # primitive OCTETSTRING, but we do check for a nested SEQUENCE
        # because it is primitive, the tag.value has been set
        # and the bytes have been read from buf already

        # TODO perhaps we should only do this for specific files
        # e.g. in .cer but not in .roa ?
        # or, really make this a second pass thingy
        # for now, we use the recurse_into_octetstring bool
        if tag.len > 0 && tag.value[1] == 0x30
            #@debug "tag.value for this OCTETSTRING contains SEQUENCE"
            subbuf = DER.Buf(tag.value)
            subtag = DER.next!(subbuf)
            if isa(subtag, Tag{InvalidTag})
                #@warn "got an InvalidTag, so, NOT an nested SEQUENCE in this OCTETSTRING?"
            elseif isa(subtag, Tag{Unimplemented})
                #@warn "in nested OCTETSTRING, got Unimplemented"
            else
                ASN.append!(me, _parse!(subtag, subbuf, indef_stack))
            end
        end
    end
    return me
end

function parse_file_recursive(fn::String) 
    recurse_into_octetstring = splitext(fn)[2] == "cer" #FIXME malloc
    fd = open(fn)
    #mmapraw = Mmap.mmap(fd, Vector{UInt8})
    #buf = DER.Buf(mmapraw)
    buf = DER.Buf(fd)
    tag = DER.next!(buf)
    close(fd)

    # this returns the actual tree, so it MUST be the last statement
    _parse!(tag, buf, Stack(0), recurse_into_octetstring)
end

function parse_append!(buf::Buf, parent::Node)
    tag = DER.next!(buf)
    result = _parse!(tag, buf, Stack(0))
    ASN.append!(parent, result)
end

function parse_value!(node::Node)
    buf = DER.Buf(node.tag.value)
    parse_append!(buf, node)
end

end #module
