#!/bin/bash

bold=$(tput bold)
normal=$(tput sgr0)
underline=$(tput smul)
nounderline=$(tput rmul)

echo -e "${bold}Wellcome to the latest version of PythonBaseApi installer.${normal}"
echo -e "${underline}Author${nounderline}: Christophe LEMOINE <pantaflex@tuta.io>"
echo -e "${underline}Copyright${nounderline}: Copyright (c)2021-2022 Christophe LEMOINE"
echo -e "${underline}License${nounderline}: MIT License"

echo -e "\nThis bash script clone from GitHub and install locally new sample project."
echo -e "When done, edit ${bold}core\settings.py${normal} and set all needed technical informations."
echo -e "Then, test your API in local with the command: ${bold}./serve.sh${normal} or ${bold}python3 -m api${normal}"

echo -e "\n${bold}Clone the repositery...${normal}"
git clone https://github.com/pantaflex44/PythonBaseApi.git

echo -e "\n${bold}Create the new API project...${normal}"
mv PythonBaseApi/ MyNewAPIProject
cd MyNewAPIProject
rm -rf .git
git init
git branch -m dev

echo -e "\n${bold}Initialize Python3 environment...${normal}"
python3 -m venv ./venv
source ./venv/bin/activate

echo -e "\n${bold}Install all dependencies...${normal}"
pip3 install -r requirements.txt

echo -e "\n${bold}Initialize sample datas...${normal}"
python3 -m api --db-install

chmod +x ./serve.sh

echo -e "\n${bold}Your good! all done.${normal}"
echo -e "Enjoy your work."
