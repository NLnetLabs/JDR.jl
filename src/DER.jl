module DER



#struct Buf
#    buffer::Array{UInt8, 1}
#    index::UInt64
#    Buf(b) = new(b, 1)
#end

struct Buf
    iob::IO
end

Buf(b::Array{UInt8,1}) = Buf(IOBuffer(b))

struct NotImplementedYetError <: Exception end

struct Tag
    class::UInt8
    constructed::Bool # PC bit
    number::UInt8
    len::Int32
    value::Array{UInt8, 1}
end

function next(buf::Buf) :: Tag
    first_byte = read(buf.iob, 1)[1]
    tagclass    = first_byte  >> 6; # bit 8-7
    PC          = first_byte & 0x20 == 0x20 # bit 6
    tagnumber   = first_byte & 0x1f # bit 5-0
    if tagnumber == 31
        throw(NotImplementedYetError())
    end
    len = Int32(read(buf.iob, 1)[1])
    value = if !PC
        read(buf.iob, len)
    else
        Array{UInt8}([]) 
    end
    return Tag(tagclass, PC, tagnumber, len, value)
end



end #module
