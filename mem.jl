using Coverage
mem = analyze_malloc("src")  # could be "." for the current directory, or "src", etc.
display(mem)
println("\n\nmalloc analysis in `mem`") 
