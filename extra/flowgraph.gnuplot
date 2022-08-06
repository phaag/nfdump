# gnuplot example command file
#
# prepare data file:
# use -r for the directory containing the flows
# ./nfdump -g -R flows > flows.csv

# Setting output to be a PNG file of size 'width'x'height'
# 'width' and 'height' are set from the command line. e.g gnuplot -e "filename='flows.csv'; width=1600; height=750;" flowgraph.gnuplot

# Setting the font of all text to be 'Verdana' size 10
set terminal pngcairo size width,height enhanced font 'Verdana,10'

# Setting the output filename to be the same as the input filename with the .png extension appended to it.
set output filename.'.png'

# We set the file separator to be the comma, this way we inform the engine that we will be processing a CSV file
set datafile separator ","

# Informing the engine that the X axis of our plot will be date/time data type
set xdata time

# We define how the date/time input must be parsed. nfdump prints the date like '2022-08-07 14:25:00'
set timefmt '%Y-%m-%d %H:%M:%S'

# Set the output format that will be shown on the X axis. Here we expect to show '07-08-2022 New Line 14:25"
set format x "%d-%m-%Y\n%H:%M"

# Set format of y label to KB, MB etc. accordingly
set format y '%.0s%cB'

# Set the X axis label
set xlabel "Time"

# Set the Y axis label
set ylabel "Bytes" 

# Enabling the Grid, this way major tick lines will be visible on the chart
set grid

# We make the zero Y axis line thicker and has a different style from the rest so that it will be easier to spot
set xzeroaxis linetype 3 linewidth 1.5

# Creating a style for the lines that will be used in the plot. Type = 1, Color = green, Width = 1
set style line 1 linetype 2 linecolor rgb "green" linewidth 1.000

# Creating a style for the lines that will be used in the plot. Type = 1, Color = red, Width = 1
set style line 2 linetype 1 linecolor rgb "red" linewidth 1.000

# Actual plot command
# It directs the engine to plot the file that is in the filename variable, use the first and forth column and use  line style with the style described above
plot filename using 1:4 with line ls 2 title 'bytes',\
