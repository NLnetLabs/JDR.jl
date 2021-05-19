# JDR.jl

[![](https://img.shields.io/badge/docs-master-blue.svg)](https://nlnetlabs.github.io/JDR.jl/master)
[![](https://img.shields.io/badge/JDR-web-green.svg)](https://jdr.nlnetlabs.nl)

JDR.jl is a Julia library to perform analysis on objects in the RPKI, enabling
you to troubleshoot specific problems or do analyse the RPKI as a whole. It's
driving [JDR](https://jdr.nlnetlabs.nl), but can be used in interactive Julia
sessions (REPL or notebooks) to iteratively explore what is in the RPKI.

## Quick-start guide

JDR processes files published in the RPKI into a logical tree structure,
allowing easy navigation between related files, collect specific values, et
cetera. See the [docs](https://nlnetlabs.github.io/JDR.jl/master) for an introduction
to those datastructures.

### Installing the JDR.jl package

Assuming you have a working Julia environment, installing JDR.jl can be done as any other
package from a git repository:
```julia-repl
]add https://github.com/NLnetLabs/JDR.jl
```

### Initial configuration

First, we need a (current) copy of the RPKI repository on disk, with a directory structure
equivalent to Routinator's rsync store, i.e. a subdirectory for every
domain/repo observed within the RPKI. See below for how to fetch these using
Routinator. The directory structure should look like this:

```
├── rsync
│   ├── repo-rpki.idnic.net
│   ├── repository.lacnic.net
│   ├── rpki.afrinic.ne
│   ├── rpki.apnic.net
│   ├── rpki.arin.net
│   ├── rpkica.twnic.tw
│   ├── rpki.cnnic.cn
│   ├── rpki.ripe.net
│   ├── rsync.rpki.nlnetlabs.nl
(...)

```

Then in `JDR.toml`, uncomment `rsyncrepo` and point it to that directory.
Furthermore, uncomment the TA certificates you want to include for analysis
when using JDR. For a full view of the RPKI, uncomment all five. It's also
possible to add new ones, i.e. testbeds.

And we're good to go! Please refer to the
[docs](https://nlnetlabs.github.io/JDR.jl/master) for examples of what you can do after
`using JDR`.


### Fetching the files from the RPKI using Routinator

**NB:** We are working on implementing fetching of RPKI files in JDR.jl itself,
so the dependency of RP software such as Routinator should go away in the near
future. As Routinator itself evolves as well, the following might become
outdated.

Using [Routinator](https://github.com/NLnetLabs/routinator/), fetch files using the
following command to ensure a compatible directory structure as shown above. Files will be
available (when using a vanilla Routinator config) in `~/.rpki-cache/repository/rsync`:
```bash
$ routinator --disable-rrdp update
```
To update the files on disk in any point in the future, run the same command. 


## Component overview

JDR is comprised of several modules:

 - `ASN1`: for decoding the RPKI files and creating ASN.1 structures
 - `PKIX`: to validate and enrich the ASN.1 structures (X509 and CMS), highlighting errors
   and extracting information
 - `RPKI`: holds the datastructures and types to represent the information extracted by the
   previous two modules, and exports methods to use and traverse all the data. This holds
   the most common types/functions for users of the library.
 - `BGP`: additional info gathered from RIPE NCC RIS data
 - `Webservice`: offering a JSON-based webservice serving as the API for [JDR](https://jdr.nlnetlabs.nl)
