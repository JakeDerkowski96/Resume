#!/bin/bash
# comile and convert to resume of all kinds
# 1. pdf
# 2. txt
# 3. docx

# DOES NOT WORK HOW IT IS SUPPOSED TO
# FIX LATER

# PREFIX
created=`date +"%Y%m%d"`
# CONTENT
resume="Jake_Derkowski_Resume"
cv="Jake_Derkowski_CV"
# EXTENTION
text=".txt"
pdf=".pdf"
doc=".docx"

function name_file { "$created-$1$2"; }

# compile tex file into pdf
function compile_resume {
	cd Latex;
	xelatex Resume.tex;
	filePDF="$created-$resume$pdf"
	mv Resume.pdf $filePDF
	latexmk -c *.tex
	xdg-open $filePDF;
	cd ..;
}

compile_resume;


function byDate {
	if [ ! -d $created ]; then
		mkdir $created;
	fi
	cp Latex/$filePDF $created/$filePDF
}

byDate;

PDF2TXT="/usr/bin/pdftotext"
function check4conversion-tool {
	if [ ! -f $PDF2TXT ]; then
		echo "Must install required tool: pdftotext";
		sudo apt-get install poppler-utils;
	fi
}

check4conversion-tool;



function resume2text {
	pdftotext -eol unix Latex/$filePDF $created/$resume$text;
}

resume2text;

WORD="/usr/bin/abiword"
function check_pdf2docx {
	if [ ! -f $WORD ]; then
		echo "Must install required tool: abiword";
		sudo apt install abiword;
	fi
}

check_pdf2docx;

function pdf2docx { abiword --to=doc $created/$filePDF; }

pdf2docx;