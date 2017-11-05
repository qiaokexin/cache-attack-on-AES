set terminal png
set output "sample_plot_all_lines.png"
set key off
file="sample_all_lines_res"

set view file
plot for [n=2:257] file u 1:n with linespoint pt 0 lt 0 lw 0.5,\
       file u 1:226 with linespoint pt 0 lt 1 lw 1


