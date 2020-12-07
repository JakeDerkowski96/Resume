#!/bin/bash
# compile and clean

function compile {
	xelatex Resume;
	xelatex CV_JakeDerkowski;
}

function clean {
	latexmk -c *".tex";
}

function open { xdg-open $1; }

compile;
clean;
open $1;
