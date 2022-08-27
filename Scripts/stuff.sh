#!/bin/bash
# compile and clean

function compile {
	xelatex resume;
    xelatex developer;
	xelatex cv;
}

function clean {
	latexmk -c *".tex";
}

function open { xdg-open $1; }

compile;
clean;
# open $1;
