macro check(name, block)
    fnname = Symbol("check_ASN1_", name)
    quote
        function $(esc(fnname))(
                                $(esc(:o))::RPKIObject{<:RPKIFile},
                                $(esc(:node))::ASN1.Node,
                                $(esc(:tpi))::TmpParseInfo,
                                $(esc(:parent_cer))::Union{Nothing, RPKIObject{CER}}=nothing)
            if tpi.nicenames
                node.nicename = $(esc(name))
            end
            $(esc(block))
        end
    end
end


