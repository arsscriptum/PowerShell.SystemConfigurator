#!/bin/bash

###############################################################################
# All This Just To Install Ruby
#                  ------------
# i have found the latest distrib version to be 18.x at
# https://github.com/nodesource/distributions/blob/master/deb/setup_18.x
#
# Last tested on 15/10/2022 on WSL Ubuntu 20.04.5
###############################################################################

sudo apt-get update -y && sudo apt-get upgrade -y
sudo apt-add-repository ppa:brightbox/ruby-ng
sudo apt-get update

cd $HOME
sudo apt-get update
sudo apt install curl
curl -sL https://deb.nodesource.com/setup_18.x | sudo -E bash -
curl -sS https://dl.yarnpkg.com/debian/pubkey.gpg | sudo apt-key add -
echo "deb https://dl.yarnpkg.com/debian/ stable main" | sudo tee /etc/apt/sources.list.d/yarn.list
sudo apt-get update
sudo apt-get install git-core zlib1g-dev build-essential libssl-dev libreadline-dev libyaml-dev libsqlite3-dev sqlite3 libxml2-dev libxslt1-dev libcurl4-openssl-dev software-properties-common libffi-dev nodejs yarn

cd
git clone https://github.com/rbenv/rbenv.git ~/.rbenv
echo 'export PATH="$HOME/.rbenv/bin:$PATH"' >> ~/.bashrc
echo 'eval "$(rbenv init -)"' >> ~/.bashrc
exec $SHELL

git clone https://github.com/rbenv/ruby-build.git ~/.rbenv/plugins/ruby-build
echo 'export PATH="$HOME/.rbenv/plugins/ruby-build/bin:$PATH"' >> ~/.bashrc
exec $SHELL

rbenv install 3.0.1
rbenv global 3.0.1
ruby -v

###############################################################################
# REQUIREMENTS
###############################################################################
sudo apt-get -y install git curl autoconf bison build-essential 
sudo apt-get -y install libssl-dev libyaml-dev libreadline6-dev zlib1g-dev
sudo apt-get -y install libncurses5-dev libffi-dev libgdbm6 libgdbm-dev libdb-dev
sudo apt-get -y install make gcc gpp build-essential zlib1g zlib1g-dev ruby-dev dh-autoreconf


###############################################################################
# GNU PG
###############################################################################
sudo apt install gnupg2
curl -sL "https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x2EE0EA64E40A89B84B2DF73499E82A75642AC823" | sudo apt-key add

###############################################################################
# RVM VM is a command-line tool which allows you to easily install, manage, 
# and work with multiple ruby environments from interpreters to sets of gems.
###############################################################################
curl -sSL https://get.rvm.io -o rvm.sh
curl -sSL https://rvm.io/mpapis.asc | gpg2 --import -
curl -sSL https://rvm.io/pkuczynski.asc | gpg2 --import -

cat ./rvm.sh | bash -s stable --rails

source /home/gp/.rvm/scripts/rvm

rvm install "ruby-3.1.2"


###############################################################################
# BUNDLER
###############################################################################

sudo gem update

sudo gem install bundler

# if you get errors (as I've done), go back to the start and go through these commands again
#sudo gem install jekyll

# inside jekyll repo
bundle install

# simple serve
bundle exec jekyll serve

# I like to have reload working and used to need force_polling to work on windows filesystem
# bundle exec jekyll serve force_polling --livereload --unpublished

bundle exec jekyll serve --livereload --unpublished --incremental