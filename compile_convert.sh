#!/bin/bash
# comile and convert to resume of all kinds
# 1. pdf
# 2. txt
# 3. docx

# PREFIX
created=`date +"%Y%m%d"`
# CONTENT
resume="Jake_Derkowski_Resume"
developer="Jake_Derkowski_Developer"
cv="cv"
# EXTENTION
text=".txt"
pdf=".pdf"
doc=".docx"

function name_file { "$created-$1$2"; }

# compile tex file into pdf
function compile_resume {
	cd Latex;
	xelatex resume.tex;
	filePDF="$created-$resume$pdf"
	mv resume.pdf $filePDF
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



function compile_dev {
	cd Latex;
	xelatex developer.tex;
	filePDF="$created-$developer$pdf"
	mv developer.pdf $filePDF
	latexmk -c *.tex
	xdg-open $filePDF;
	cd ..;
}

compile_dev;
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
