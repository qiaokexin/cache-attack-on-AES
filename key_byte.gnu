set terminal png size 2048, 1096
set output "current.png"
set key off
file="outq"

set view file
set xrange[0:256]
set yrange[0.9:1]

set multiplot layout 4,4

do for [n=2:17]{
plot file u 1:n with linespoint pt 0 lt 3 lw 1
}


