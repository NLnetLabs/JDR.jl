module PKIX
using ...JDR.Common
using ..ASN1
using ...JDR.RPKICommon

# for the uses of @check in X509 and CMS:
using SHA 
using IntervalTrees
using Sockets

macro check(name, block)
    fnname = esc(Symbol("check_ASN1_$(name)"))
    :(
      esc(
      function $fnname(o::RPKIObject{T}, node::ASN1.Node, tpi::TmpParseInfo) where T
          if tpi.setNicenames
              node.nicename = $name
          end
          esc($block)
      end
     )
     )
end


export X509
include("X509.jl")
include("CMS.jl")

end
