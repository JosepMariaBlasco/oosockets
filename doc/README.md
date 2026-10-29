# ooSockets' chapter of the ooRexx documentation

`rexxextensions/` holds a chapter for ooRexx's *Rexx Extensions Library
Reference* (`docs/trunk/rexxextensions` in ooRexx's Subversion
repository), written in the style of the chapters already there
(`logicalwrapper.xml`, `jsoncls.xml`, `yamlcls.xml`), so that it can go
into ooRexx together with the classes. The paths below `rexxextensions/`
are the same as in ooRexx's tree:

| File | What it is |
|---|---|
| `en-US/socketscls.xml` | the chapter (DocBook 4.5), *Sockets (Package "sockets.cls")* |
| `en-US/images/sockets.ebnf` | the grammar of the syntax diagrams |
| `en-US/images/sockets.xhtml` | the diagrams as the Railroad Diagram Generator makes them |
| `en-US/images/sockets/*.svg` | the 92 diagrams the chapter shows |

Written against docs/trunk r13306 (27/10/2026).

## Adding it to the book

Copy the files to the same places in a working copy of `docs/trunk`, and
include the chapter in `rexxextensions/en-US/rexxextensions.xml`, in
alphabetical order (after `logicalwrapper.xml`):

```xml
	<xi:include href="socketscls.xml" xmlns:xi="http://www.w3.org/2001/XInclude" />
```

## Building

With the highlighting variant of the build tools,
`docs/trunk/tools/bldoc_orx/hl*.rex`, which need the Rexx Parser
(<https://rexx.epbcn.com/rexx-parser/>, its `bin/` on `REXX_PATH`), and
`xsltproc`, Apache FOP and the DocBook XSL style sheets:

```sh
cd docs/trunk/tools/bldoc_orx
rexx docpath.rex /path/to/docs/trunk
rexx hldocprep.rex rexxextensions
rexx hldoc2pdf.rex            # pdf_files/rexxextensions.pdf
rexx hldoc2HTML.rex           # html_folders/rexxextensions/
```

Built so on 27/10/2026 (Ubuntu 24.04, ooRexx r13297, Rexx Parser 0.7):
the chapter is valid DocBook 4.5, has no broken links and adds no FOP
warnings of its own; every example that can run without the Internet was
run as it is, against ooSockets built from this repository.

## The syntax diagrams

As `docs/trunk/tools/RailRoadDiagrams/RailDiagramGenerator-readme.txt`
says (without inlining literals), from `en-US/images/`:

```sh
java -jar .../tools/RailRoadDiagrams/rr-1.67-java8/rr.war -noinline -out:sockets.xhtml sockets.ebnf
rexx .../tools/RailRoadDiagrams/extract_svg_from_rr_xhtml.rex sockets.xhtml
mv socket_*.svg serverSocket_*.svg tlsSocket_*.svg tlsServerSocket_*.svg tlsOptions_*.svg \
   udpSocket_*.svg multicastSocket_*.svg dtlsSocket_*.svg dtlsServerSocket_*.svg \
   datagram_*.svg sockets/
```

## Keeping it current

The chapter describes the classes as they are. One point is still open
with Rony G. Flatscher: whether every error of the TLS and DTLS classes
says `TLS error:`, also when the socket underneath failed.
