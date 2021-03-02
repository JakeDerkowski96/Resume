#!/bin/bash
# comile and convert to resume of all kinds
# 1. pdf
# 2. txt
# 3. docx

# PREFIX
created=`date +"%Y%m%d"`
# CONTENT
resume="Jake_Derkowski_Resume"
DEV="Jake_Derkowski_DEV"
cv="cv"
# EXTENTION
text=".txt"
pdf=".pdf"
doc=".docx"

# name file appropriately
function name_file { "$created-$1$2"; }


# NAMEING FILES
RnamePDF=name_file "$resume$pdf"


echo $RnamePDF
sleep 5
# DnamePDF=$created

# organize by date
function byDate {
	if [ ! -d $created ]; then
		mkdir $created;
	fi
	cp Latex/$filePDF $created/$filePDF
}

byDate;


# check for dependancies
PDF2TXT="/usr/bin/pdftotext"
function check4conversion-tool {
	if [ ! -f $PDF2TXT ]; then
		echo "Must install required tool: pdftotext";
		sudo apt-get install poppler-utils;
	fi
}

check4conversion-tool;

# abiword dependacy
WORD="/usr/bin/abiword"
function check_pdf2docx {
	if [ ! -f $WORD ]; then
		echo "Must install required tool: abiword";
		sudo apt install abiword;
	fi
}


# COMPILE


# # compile tex file into pdf ~~RESUME
# function compile_resume {
# 	cd Latex;
# 	xelatex resume.tex;
# 	filePDF="$created-$resume$pdf"
# 	mv resume.pdf $filePDF
# 	latexmk -c *.tex
# 	xdg-open $filePDF;
# 	cd ..;
# }

# compile_resume;


# # compile tex file into pdf ~~ DEV
# function compile_dev {
# 	cd Latex;
# 	xelatex DEV.tex;
# 	filePDF="$created-$DEV$pdf"
# 	mv DEV.pdf $filePDF
# 	latexmk -c *.tex
# 	xdg-open $filePDF;
# 	cd ..;
# }

# compile_dev;
# # byDate;







function resume2text { pdftotext -eol unix Latex/$filePDF $created/$resume$text; }

resume2text;



check_pdf2docx;

function pdf2docx { abiword --to=doc $created/$filePDF; }

pdf2docx;
