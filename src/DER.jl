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




function next!(buf::Buf) #:: Tag{<:AbstractTag} #:: Union{Tag{<:AbstractTag}, Nothing}
    #_tmp = Vector{UInt8}(undef, 1) 
    #readbytes!(buf.iob, _tmp, 1) 
    #first_byte = _tmp[1] 
    first_byte = lookahead(buf)

    tagclass    = first_byte  >> 6; # bit 8-7
    constructed = first_byte & 0x20 == 0x20 # bit 6
    tagnumber   = first_byte & 0x1f # bit 5-0
    if tagnumber == 31
        longtag = 0

        byte = lookahead(buf)
        while byte & 0x80 == 0x80 # first bit is 1
            longtag = (longtag << 7) | (byte & 0x7f) # take the last 7 bits
            byte = buf.iob.data[buf.iob.ptr]
            buf.iob.ptr += 1
        end
        tagnumber = (longtag << 7) | (byte & 0x7f) # take the last 7 bits
    end

    lenbyte = buf.iob.data[buf.iob.ptr]
    buf.iob.ptr += 1
    len_indef = lenbyte == 0x80
    len = Int32(lenbyte)

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
        res::Int32 = 0
        for o in octets
            res = (res << 8) | o
        end
        len = res
    end
    # check for cases where we are parsing something that is not a (valid) tag
    if len < 0
        return Tag{InvalidTag}()
    elseif len > (buf.iob.size - buf.iob.ptr + 1) 
        #@warn "length $(len) goes beyond end of buffer $(buf.iob.size) - $(buf.iob.ptr), returning InvalidTag"
        return Tag{InvalidTag}()
    end
    @assert(len >= 0)

    value = if len_indef
        #@warn "indef len, not reading value"
        #[]
        nothing
    #elseif tagnumber == 16 # FIXME also include SET ?
    #    nothing
    elseif !constructed
        read(buf.iob, len) 
    else
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

function _parse!(tag, buf, indef_stack::Stack)
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
    end
    return me
end

function parse_file_recursive(fn::String) 
    fd = open(fn)
    #mmapraw = Mmap.mmap(fd, Vector{UInt8})
    #buf = DER.Buf(mmapraw)
    buf = DER.Buf(fd)
    tag = DER.next!(buf)
    close(fd)

    # this returns the actual tree, so it MUST be the last statement
    _parse!(tag, buf, Stack(0))
end

function parse_replace_children!(buf::Buf, to_replace::Node)
    tag = DER.next!(buf)
    result = _parse!(tag, buf, Stack(0))
    to_replace.children = [result]
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
