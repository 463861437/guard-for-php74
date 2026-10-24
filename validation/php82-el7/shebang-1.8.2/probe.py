from __future__ import print_function
import hashlib,json,os,re,shutil,subprocess,tempfile
root=tempfile.mkdtemp(prefix='phpguard-shebang-',dir='/tmp')
probe=os.path.join(root,'argv-probe')
with open(probe+'.c','w') as h:
 h.write('#include <stdio.h>\nint main(int argc,char **argv){int i; for(i=0;i<argc;++i) puts(argv[i]);return 0;}\n')
subprocess.check_call(['gcc','-o',probe,probe+'.c'])
results=[]
for length in (122,123,250,251):
 interpreter=root+'/'+('x'*(length-len(root)-1))
 assert len(interpreter.encode('ascii'))==length
 os.symlink(probe,interpreter)
 script=os.path.join(root,'case-%s.sh'%length)
 with open(script,'w') as h:h.write('#!'+interpreter+' -n\nignored body\n')
 os.chmod(script,0o700)
 output=subprocess.check_output([script]).decode().splitlines()
 results.append({'interpreter_path_bytes':length,'shebang_bytes_without_newline':2+length+3,'argv':output,'optional_argument':output[1]})
 assert output[1]==('-' if length==251 else '-n'),output
binary='/home/phpguardbuild/php82-ci-compat/scl/build-1MaDMm/rpmbuild/BUILD/php-8.2.35/build-fpm/sapi/cli/php'
short=os.path.join(root,'php')
shutil.copyfile(binary,short)
os.chmod(short,0o700)
source='/inputs/source-test/php-8.2.35'
for name in ('run-tests.php','sapi/cli/tests/021.phpt','sapi/cli/tests/skipif.inc'):
 target=os.path.join(root,name)
 if not os.path.isdir(os.path.dirname(target)):os.makedirs(os.path.dirname(target))
 shutil.copyfile(os.path.join(source,name),target)
case=os.path.join(root,'sapi/cli/tests/021.phpt')
with open(case,'rb') as h:casehash=hashlib.sha256(h.read()).hexdigest()
with open(binary,'rb') as h:binaryhash=hashlib.sha256(h.read()).hexdigest()
env=dict(os.environ,TEST_PHP_EXECUTABLE=short,NO_INTERACTION='1',REPORT_EXIT_STATUS='1',PHP_INI_SCAN_DIR='/dev/null',PHPRC='/dev/null',LC_ALL='C',LANG='C')
log=os.path.join(root,'021-short-path.log')
with open(log,'wb') as h:code=subprocess.call([short,'-n',os.path.join(root,'run-tests.php'),'-n','-q','sapi/cli/tests/021.phpt'],cwd=root,env=env,stdout=h,stderr=subprocess.STDOUT)
with open(log,'rb') as h:logtext=h.read().decode()
assert code==0,logtext
assert 'PASS CLI shell shebang [sapi/cli/tests/021.phpt]' in re.sub(r'\x1b\[[0-9;]*m', '', logtext),logtext
result={'kind':'linux_shebang_boundary_and_php82_cli_regression','kernel':subprocess.check_output(['uname','-sr']).decode().strip(),'fixture_distribution':'CentOS 7 userspace','kernel_limit_tested':'modern 256-byte Linux interpreter buffer, not an EL7 3.10 kernel','directory':root,'cases':results,'php_test':{'source':'unmodified PHP8.2.35 sapi/cli/tests/021.phpt','source_sha256':casehash,'binary':binary,'binary_sha256':binaryhash,'version':subprocess.check_output([short,'-n','-r','echo PHP_VERSION;']).decode(),'short_binary':short,'short_shebang_bytes_without_newline':len(short.encode())+5,'exit_code':code,'result':'PASS','log':log},'php_runtime_packages_changed':False,'full_php_build_rerun':False}
with open(os.path.join(root,'result.json'),'w') as h:json.dump(result,h,indent=2,sort_keys=True)
print(json.dumps(result,indent=2,sort_keys=True))
