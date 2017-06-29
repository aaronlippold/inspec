# encoding: utf-8
# copyright: 2017
# author: Aaron Lippold, lippold@gmail.com
# author: Rony Xavier, rx294@nyu.edu

require 'helper'
require 'inspec/resource'

describe 'Inspec::Resources::Nginx' do
  describe 'NGINX Methods' do
    it 'Verify nginx parsing `support_info` - `TLS SNI`' do
      resource = load_resource('nginx')
      _(resource.support_info).must_match 'TLS SNI'
    end
    it 'Verify nginx parsing `openssl_version` - `1.0.1e-fips/11 Feb 2013`' do
      resource = load_resource('nginx')
      _(resource.openssl_version.date).must_match '11 Feb 2013'
      _(resource.openssl_version.version).must_match '1.0.1e-fips'
    end
    it 'Verify nginx parsing `compiler_info` - `gcc 4.8.5 20150623 (Red Hat 4.8.5-4) (GCC)`' do
      resource = load_resource('nginx')
      _(resource.compiler_info.compiler).must_match 'gcc'
      _(resource.compiler_info.version).must_match '4.8.5'
      _(resource.compiler_info.date).must_match '20150623'
    end
  end

  describe 'NGINX Paramaters' do
    it 'Verify nginx parsing `version` - 1.12.0' do
      resource = load_resource('nginx')
      _(resource.version).must_match '1.12.0'
    end
    it 'Verify nginx_module parsing with custom path`version` - 1.12.0' do
      resource = load_resource('nginx','/usr/sbin/')
      _(resource.version).must_match '1.12.0'
    end
    it 'Verify nginx parsing `service` - `nginx`' do
      resource = load_resource('nginx')
      _(resource.service).must_match 'nginx'
    end
    it 'Verify nginx parsing `conf_path` - `/etc/nginx`' do
      resource = load_resource('nginx')
      _(resource.conf_path).must_match '/etc/nginx/nginx.conf'
    end
    it 'Verify nginx parsing `conf_dir` - `/etc/nginx`' do
      resource = load_resource('nginx')
      _(resource.conf_dir).must_match '/etc/nginx'
    end
    it 'Verify nginx parsing `prefix` - `/etc/nginx`' do
      resource = load_resource('nginx')
      _(resource.prefix).must_match '/etc/nginx'
    end
    it 'Verify nginx parsing `sbin_path` - `/usr/sbin/nginx`' do
      resource = load_resource('nginx')
      _(resource.sbin_path).must_match '/usr/sbin/nginx'
    end
    it 'Verify nginx parsing `modules_path` - `/usr/lib64/nginx/modules`' do
      resource = load_resource('nginx')
      _(resource.modules_path).must_match '/usr/lib64/nginx/modules'
    end
    it 'Verify nginx parsing `error_log_path` - `/var/log/nginx/error.log`' do
      resource = load_resource('nginx')
      _(resource.error_log_path).must_match '/var/log/nginx/error.log'
    end
    it 'Verify nginx parsing `error_log_path` - `/var/log/nginx/access.log`' do
      resource = load_resource('nginx')
      _(resource.http_log_path).must_match '/var/log/nginx/access.log'
    end
    it 'Verify nginx parsing `lock_path` - `/var/run/nginx.lock`' do
      resource = load_resource('nginx')
      _(resource.lock_path).must_match '/var/run/nginx.lock'
    end
    it 'Verify nginx parsing `http_client_body_temp_path` - `/var/cache/nginx/client_temp`' do
      resource = load_resource('nginx')
      _(resource.http_client_body_temp_path).must_match '/var/cache/nginx/client_temp'
    end
    it 'Verify nginx parsing `http_proxy_temp_path` - `/var/cache/nginx/proxy_temp`' do
      resource = load_resource('nginx')
      _(resource.http_proxy_temp_path).must_match '/var/cache/nginx/proxy_temp'
    end
    it 'Verify nginx parsing `http_fastcgi_temp_path` - `/var/cache/nginx/fastcgi_temp`' do
      resource = load_resource('nginx')
      _(resource.http_fastcgi_temp_path).must_match '/var/cache/nginx/fastcgi_temp'
    end
    it 'Verify nginx parsing `http_uwsgi_temp_path` - `/var/cache/nginx/uwsgi_temp`' do
      resource = load_resource('nginx')
      _(resource.http_uwsgi_temp_path).must_match '/var/cache/nginx/uwsgi_temp'
    end
    it 'Verify nginx parsing `http_scgi_temp_path` - `/var/cache/nginx/scgi_temp`' do
      resource = load_resource('nginx')
      _(resource.http_scgi_temp_path).must_match '/var/cache/nginx/scgi_temp'
    end
    it 'Verify nginx parsing `http_scgi_temp_path` - `/var/cache/nginx/scgi_temp`' do
      resource = load_resource('nginx')
      _(resource.http_scgi_temp_path).must_match '/var/cache/nginx/scgi_temp'
    end
  end
end
