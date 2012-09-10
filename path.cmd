set title "I/O statistics per path"
set key outside
#set style histogram cluster gap 1
set style histogram rowstacked
set style data histogram
set style fill solid
set boxwidth 0.75

set xlabel "Path"
set ylabel "No. of I/O"
set xtics nomirror rotate by -45 font ",8"

plot 'dioparse.path.dat' using 2:xtic(1) title "read" with histograms linecolor rgb 'dark-blue', '' using 3 title "write" with histograms linecolor rgb 'forest-green'

