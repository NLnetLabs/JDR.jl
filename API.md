# JDR API documentation

The API offers two ways to search for resources: `/asn/$asn` and
`/prefix/$prefix`, and one way to get a overview of the global repository
represented in publication points via `/pp`. All results are formatted as a
tree, compatible with the Vue-Tree-Chart plugin.

By appending `/raw` at the end of the URL, results are returned as individual
branches instead of the tree. 


Details for objects (i.e. certificates, manifests or ROAs) can be retrieved via
`/object/$escaped_filename`

All endpoints are exposed on `/api/v1/`, e.g. `/api/v1/asn/1234`

Responses are wrapped in an envelope describing meta-data, the requested
information is located in the `data` child:

```
{
    "last_update":"2020-04-14T14:53:33.3",
    "serial":4,
    "timestamp":"2020-04-14T14:55:53.442",
    "data":[ ... ]
}

```

## General publication point overview via `/pp`

The publication point tree (pp tree) is a tree comprised of the certificates
(CER) where a new delegation is observed. The root of this tree has no object
attached to it. Its children are the RIR publication points, et cetera. Every
node in the tree contains the following:

 * **children**: more of this same node, recursively
 * **mates**: empty for now
 * **name**: a string representing the hostname of this publication point, e.g.
   `rpki.ripe.net`
 * **object**: the _object_, which is always a CER, as described below.

The pp tree is meant to show overall status / health of the public repositories,
but not all prefixes for which ROAs have been created or any other detailed
information. The _object_ does contain a *details_url* to go to a detailed view
(`/object`) for the certificate. It also contains _remark_ counts (both `_me`
and `_children`, respectively showing warning/error counts for itself and all of
its children, recursively).


## Searching via `/asn` and `/prefix`

Searches for ROAs where the ASN or the prefix occurs. For ASNs, only exact
matches are returned. For prefixes, ROAs with the prefix itself (if any) or ROAs
with the first less-specific covering the passed prefix are returned.

In both cases, the `data` field in the response contains a tree (Vue-Tree-Chart
compatible) of objects from an empty root node down to the actual ROA, with only
CER nodes in between. Every such node contains the following:

 * **children**: more of this same node, recursively
 * **mates**: for CER nodes, this contains the manifest
 * **name**: the filename this node represents (ending in .cer, .mft or .roa)
 * **object**: the _object_ which is a CER, MFT or for the very last node, the
   ROA 

Every _object_, regardless of its exact type, contains the following:

 * **filename**: filename on filesystem 
 * **details_url**: URL to do a /object/ request (for ease of development/troubleshooting)
 * **object**: the specific object (CER/MFT/ROA/CRL), see below
 * **objecttype**: string specifying what *object* is in this result, i.e. CER/MFT/ROA/CRL
 * **remarks**: list of remarks for this *object*. A *remark* consists of:
    * **lvl**: string representing the severeness of this annotation. For now,
       we have `DBG/INFO/WARN/ERR`.
    * **msg**: the actual annotation
 * **remark_counts_me**: sum of remarks for the *object* and *object.tree*
 * **remark_counts_children**: :construction: sum of remarks of the children of this node,
   recursively. *NB*: the counts are summed in the full RPKI repository tree in
   the backend, where manifests are considered 'children' of certificates. This
   possibly produces unexpected numbers when looking at `/pp` results, for
   example.

If `/raw` is appended to the URL, for example `/api/v1/asn/1234/raw`, the
results are not formatted as a tree, but as an array: this array contains, for every ROA matching the
search query, a list of _objects_ going from ROA to the CER of the RIR, with the
related manifests and resource certificates in order. Thus, instead of a 'from
the root' perspective, the `/raw` results are more like a backtrace from the ROA
back to the root. (This was the original behavior of the `/asn` and `/prefix`
endpoints!)



### object types: CER/MFT/ROA

The *object* field contains information specific to the parsed RPKI object
type. For example, for a `"objecttype": "ROA"`, thus a `.roa` file, the
*object* consists of:

 * **asid**: the AS number in the ROA
 * **vrps**: the array of prefixes in the ROA, each consisting of:
   * **prefix**: a IPv6 or IPv4 prefix
   * **maxlength**: the maxLength for this prefix


Similarly, a manifest (*objecttype* `MFT`) contains:

 * **files**: files listed in this manifest
 * **loops**: if any loops are observed between this manifest and a certificate
                listed in *files*, those certificates are listed here
 * **missing_files**: files listed in *files* but not on the filesystem 
 * **this_update**: timestamp
 * **next_update**: timestamp


For certificates (*objecttype* `CER`):

 * **pubpoint**: rsync URL for the publication point of this resource certificate
 * **manifest**: manifest URL
 * **rrdp_notify**: RRDP notification URL
 * **inherit_prefixes**: boolean stating whether prefixes from a parent certificate are inherited
 * **prefixes**: list of IPv6 and IPv4 prefixes
 * **inherit_ASNs**: boolean stating whether ASNs from a parent certificate are inherited
 * **ASNs**: list of single ASNs and tuples of two ASNs describing a range


## Object details via `/object`

The list of objects in responses to `/asn` and `/prefix` contain slimmed down
versions of the RPKI objects. Most notably, the parsed and annotated ASN.1
content of the actual files is left out. In some cases, we might leave out the
*prefixes* and/or *ASNs* in certificates, or the *files* in a manifest, simply
because the responses to most search queries get way too large otherwise.

Using the *filename* from the search results in a request to `/object` however
gives all the information for that file:

 * **filename**: basename of this file 
 * **tree**: the parsed and annotated ASN.1 tree. It starts with one single root
   node containing one or more children. Every node has a:
   * **children**: the list of children, possibly `null` for an empty list
   * **tag**: the ASN.1 tag type with the length of the tag in parentheses
   * **validated**: boolean stating whether we have actively checked this ASN.1
     tag (FIXME: the term 'validated' is ambiguous in context of RPKI/ROV)
   * **remarks**: list of annotations for this tag, possibly null for an empty
     list. Same levels as used in the *remarks* for *object*s.
 * **object**: see `CER/MFT/ROA` section above
 * **objecttype**: see above
 * **remarks**: see above
 * **remark_counts_me**: see above



# Example responses

Example response to a request for `/api/v1/asn/199664`:
```
{
  "last_update": "2020-04-14T15:03:46.546",
  "serial": 6,
  "timestamp": "2020-04-14T15:07:13.371",
  "data": [
    [
      {
        "filename": "/home/luuk/.rpki-cache/repository/rsync/rsync.rpki.nlnetlabs.nl/repo/ca/0/326130343a623930303a3a2f3239203d3e20313939363634.roa",
        "details_url": "http://localhost:8081/api/v1/object/%2Fhome%2Fluuk%2F.rpki-cache%2Frepository%2Frsync%2Frsync.rpki.nlnetlabs.nl%2Frepo%2Fca%2F0%2F326130343a623930303a3a2f3239203d3e20313939363634.roa",
        "object": {
          "asid": 199664,
          "vrps": [
            {
              "prefix": "2a04:b900::/29",
              "maxlength": 29
            }
          ]
        },
        "objecttype": "ROA",
        "remarks": null,
        "remark_counts_me": {
          "DBG": 0,
          "INFO": 1,
          "ERR": 0,
          "WARN": 0
        }
      },
      {
        "filename": "/home/luuk/.rpki-cache/repository/rsync/rsync.rpki.nlnetlabs.nl/repo/ca/0/C9FCBF0173D9425FD3EF343EBEA41EA62193B64D.mft",
        "details_url": "http://localhost:8081/api/v1/object/%2Fhome%2Fluuk%2F.rpki-cache%2Frepository%2Frsync%2Frsync.rpki.nlnetlabs.nl%2Frepo%2Fca%2F0%2FC9FCBF0173D9425FD3EF343EBEA41EA62193B64D.mft",
        "object": {
          "files": [
            "326130343a623930303a3a2f3239203d3e2038353837.roa",
            "326130343a623930303a3a2f3239203d3e20313939363634.roa",
            "C9FCBF0173D9425FD3EF343EBEA41EA62193B64D.crl",
            "3138352e34392e3134302e302f3232203d3e2038353837.roa",
            "3138352e34392e3134302e302f3232203d3e20313939363634.roa"
          ],
          "loops": null,
          "missing_files": null,
          "this_update": "2020-03-29T19:55:00.0",
          "next_update": "2020-03-30T20:00:00.0"
        },
        "objecttype": "MFT",
        "remarks": null,
        "remark_counts_me": {
          "DBG": 0,
          "INFO": 1,
          "ERR": 0,
          "WARN": 0
        }
      },
      {
        "filename": "/home/luuk/.rpki-cache/repository/rsync/rpki.ripe.net/repository/DEFAULT/yfy_AXPZQl_T7zQ-vqQepiGTtk0.cer",
        "details_url": "http://localhost:8081/api/v1/object/%2Fhome%2Fluuk%2F.rpki-cache%2Frepository%2Frsync%2Frpki.ripe.net%2Frepository%2FDEFAULT%2Fyfy_AXPZQl_T7zQ-vqQepiGTtk0.cer",
        "object": {
          "pubpoint": "rsync://rsync.rpki.nlnetlabs.nl/repo/ca/0/",
          "manifest": "rsync://rsync.rpki.nlnetlabs.nl/repo/ca/0/C9FCBF0173D9425FD3EF343EBEA41EA62193B64D.mft",
          "rrdp_notify": "https://rrdp.rpki.nlnetlabs.nl/rrdp/notification.xml",
          "inherit_prefixes": false,
          "prefixes": [
            "185.49.140.0/22",
            "2a04:b900::/29"
          ],
          "inherit_ASNs": false,
          "ASNs": []
        },
        "objecttype": "CER",
        "remarks": null,
        "remark_counts_me": {
          "DBG": 0,
          "INFO": 0,
          "ERR": 0,
          "WARN": 0
        }
      },
      {
        "filename": "/home/luuk/.rpki-cache/repository/rsync/rpki.ripe.net/repository/DEFAULT/KpSo3VVK5wEHIJnHC2QHVV3d5mk.mft",
        "details_url": "http://localhost:8081/api/v1/object/%2Fhome%2Fluuk%2F.rpki-cache%2Frepository%2Frsync%2Frpki.ripe.net%2Frepository%2FDEFAULT%2FKpSo3VVK5wEHIJnHC2QHVV3d5mk.mft",
        "object": {
          "files": [
            "0-eIYY3lhDxjDvPOYo2wXzWwscQ.cer",
            "0-jUy45ELsOKa8P6QAoqUXzuDR4.cer",
( ... )
```

If we then construct a request to `/object` (or use the *details_url*) from the
ROA we found for that ASN, thus
`/api/v1/object/%2Fhome%2Fluuk%2F.rpki-cache%2Frepository (... cut ...) e20313939363634.roa `
the response looks like:

```
{
  "last_update": "2020-04-15T08:58:51.048",
  "serial": 82,
  "timestamp": "2020-04-15T09:01:05.263",
  "data": {
    "filename": "3138352e34392e3134302e302f3232203d3e20313939363634.roa",
    "tree": {
      "children": [
        {
          "children": null,
          "tag": "OID (9)",
          "validated": true,
          "remarks": null
        },
        {
          "children": [
            {
              "children": [
                {
                  "children": null,
                  "tag": "INTEGER (1)",
                  "validated": true,
                  "remarks": null
                },
                {
                  "children": [
                    {
                      "children": [
                        {
                          "children": null,
                          "tag": "OID (9)",
                          "validated": true,
                          "remarks": null
                        },
                        {
                          "children": null,
                          "tag": "NULL (0)",
                          "validated": true,
                          "remarks": [
                            {
                              "lvl": "INFO",
                              "msg": "this NULL SHOULD be absent (RFC4055)"
                            }
                          ]
                        }
                      ],

```
