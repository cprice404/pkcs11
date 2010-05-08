# -*- coding: utf-8 -*-
# -*- ruby -*-

require 'rubygems'
require 'hoe'
require 'rake/extensiontask'

hoe = Hoe.spec 'pkcs11' do
  developer('Ryosuke Kutsuna', 'ryosuke@deer-n-horse.jp')
  developer('GOTOU Yuuzou', 'gotoyuzo@notwork.org')
  developer('Lars Kanis', 'kanis@comcard.de')
  
  self.readme_file = 'README.rdoc'
  self.extra_rdoc_files << self.readme_file
  spec_extras[:extensions] = 'ext/extconf.rb'
end

ENV['RUBY_CC_VERSION'] = '1.8.6:1.9.1'

Rake::ExtensionTask.new('pkcs11_ext', hoe.spec) do |ext|
  ext.ext_dir = 'ext'
  ext.cross_compile = true                # enable cross compilation (requires cross compile toolchain)
  ext.cross_platform = ['i386-mswin32', 'i386-mingw32']     # forces the Windows platform instead of the default one
end

# vim: syntax=ruby