#
# The functions in this file are available in all WLST sessions within the daemon. You can use
# them in all actions.
#
import re
import jarray
import javax.management.ObjectName

domain = ''

def quote(text):
    if text or text == '':
        return "\"" + str(text).replace("\"", "\"\"") + "\""
    else:
        return ""

def open_file(fields):
    f = open("/tmp/wlstScript.out", "w")
    print >>f, fields
    return f

def report_back_success():
    print "~~~~COMMAND SUCCESFULL~~~~"

def report_back_error():
    print "~~~~COMMAND FAILED~~~~"

def add_index_entry(file_handle, values):
    print "Adding index entry (inside function)"
    print >>file_handle, ";".join(map(quote, values))
    print "Index entry added (inside function)"

def translate(value):
    if value == 'true':
        return '1'
    elif value == 'false':
        return '0'
    else:
        return str(value)

def format_boolean(value):
    if value == '1' or value == 1:
        return 'True'
    else:
        return 'False'

def format_boolean2(value):
    if value == '1' or value == 1:
        return true
    else:
        return false

def create_boot_properties_file(directory_path, file_name, username, password):
    server_dir = File(directory_path)
    bool = server_dir.mkdirs()
    full_file_name = directory_path + '/' + file_name
    file_new=open(full_file_name, 'w')
    file_new.write('username=%s\n' % username)
    file_new.write('password=%s\n' % password)
    file_new.flush()
    file_new.close()
    os.system('chmod 600 ' + full_file_name)

def retrieve_target_list(wlst_name):
    cd(wlst_name)
    nn = ls('Targets', returnMap='true')
    target     = []
    targetType = []
    for token_target in nn:
        target.append(token_target)
        cd(wlst_name + '/Targets/'+token_target)
        targetType.append(get('Type'))
    return target, targetType

def target_list(targets, targettypes):
    targetList = []
    for i in range(len(targets)):
        bean = ObjectName('com.bea:Name=' + targets[i] + ',Type='+targettypes[i])
        targetList.append(bean)
    return jarray.array(targetList, ObjectName)

def password_to_string(value):
    if value == None:
        return None
    else:
        string_value = ''
        for byte in value:
            string_value = string_value + chr(byte)
        return string_value

def decrypt_value(encrypted_value):
    domain_dir = get('RootDirectory')
    domain_dir_path = os.path.abspath(domain_dir)
    encrypt_srv = weblogic.security.internal.SerializedSystemIni.getEncryptionService(domain_dir_path)
    ces = weblogic.security.internal.encryption.ClearOrEncryptedService(encrypt_srv)
    password = ces.decrypt(encrypted_value)
    return password

def type_for(key):
    key_description = man(key)
    type_array = re.search("\|interfaceclassname : (.*)\|\|", key_description)
    if type_array:
        return type_array.group(1)
    else:
        return 'str'

def is_encrypted(full_key):
    elements = full_key.split('/')
    key      = elements.pop()
    path     = '/'.join(elements)
    print path
    print key
    old_path = pwd()
    cd(path)
    key_description = man(key)
    cd(old_path)
    encrypted = re.search("\|(?:com.bea.)?encrypted : (true)\|\|", key_description) != None
    if encrypted:
        print 'attribute ' + full_key + ' is encrypted.'
    else:
        print 'attribute ' + full_key + ' is NOT encrypted.'
    return encrypted

def auto_typed_set(key, value):
    key_type = type_for(key)
    #
    # Don't do anything if the value is not specified
    #
    if value == None:
        return
    if key_type == 'int': # or key_type == 'long':
        if value.strip(): # Value is a non empty string
            print 'Setting integer property ' + key + ' to ' + value
            set(key,int(value))
    elif key_type == 'boolean':
        if value.strip(): # Value is a non empty string
            print 'Setting boolean property ' + key + ' to ' + value
            if value == 'True' or value == 'true' or value == '1':
                real_value = 'true'
            else:
                real_value = 'false'
        set(key,real_value)
    elif key_type == 'float':
        if value.strip(): # Value is a non empty string
            print 'Setting float property ' + key + ' to ' + value
            set(key,float(value))
    elif key_type == 'array':
        if value.strip(): # Value is a non empty string
            print 'Setting array property ' + key + ' to ' + value
            set(key, jarray.array(value, String))
    else:
        print 'Setting generic property ' + key + ' to ' + value
        set(key,value)

def set_attribute_value(mbean_attribute, value = None):
    print "set att " + mbean_attribute + " with value " + str(value)
    attribute_fields = ['interfaceclassname', 'defaultValue', 'com.bea.defaultValueNull']
    try:
        fields = getMBI().getAttribute(mbean_attribute).getDescriptor().getFieldValues(attribute_fields)
    except:
        print "error retrieving fields do ls()"
        ls()
        print "Unexpected error:", sys.exc_info()[0]
        raise
    print fields
    key_type      = fields[0]
    # have default value
    default_value = fields[1]
    # defaulvalue is null
    null_value    = fields[2]
    #
    # if the value is not specified set the default value if it defined
    if value:
        attribute_value = str(value)
    else:
        print "found empty value, try to use the defaults"
        if default_value != None:
            # assign default to value
            print 'found default value instead of empty'
            attribute_value = str(default_value)
        elif null_value == 1:
            # set None and return
            set(mbean_attribute, None)
            return
        else:
            return
    if key_type == 'int': # or key_type == 'long':
        # possible check min max
        if attribute_value.strip(): # Value is a non empty string
            print 'Setting integer property ' + mbean_attribute + ' to ' + attribute_value
            set(mbean_attribute, int(attribute_value))
    elif key_type == 'boolean':
        if attribute_value.strip(): # Value is a non empty string
            print 'Setting boolean property ' + mbean_attribute + ' to ' + attribute_value
            if attribute_value == 'True' or attribute_value == 'true' or attribute_value == '1':
                real_value = 'True'
            else:
                real_value = 'False'
            set(mbean_attribute, real_value)
    elif key_type == 'float':
        if attribute_value.strip(): # Value is a non empty string
            print 'Setting float property ' + mbean_attribute + ' to ' + attribute_value
            set(mbean_attribute, float(attribute_value))
    else:
        print 'Setting generic property ' + mbean_attribute + ' to ' + attribute_value
        set(mbean_attribute, attribute_value)

# print 'end of common'


cd("/")
m = ls('/Servers',returnMap='true')

f = open_file("name;listenaddress;listenport;logintimeout;ssllistenport;sslenabled;sslhostnameverificationignored;sslhostnameverifier;two_way_ssl;client_certificate_enforced;useservercerts;machine;cluster;logfilename;log_file_min_size;log_filecount;log_rotate_logon_startup;log_rotationtype;log_number_of_files_limited;tunnelingenabled;log_http_filename;log_http_format;log_http_format_type;log_datasource_filename;classpath;arguments;jsseenabled;domain;custom_identity;custom_identity_keystore_filename;trust_keystore_file;custom_identity_alias;default_file_store;max_message_size;log_redirect_stderr_to_server;log_redirect_stdout_to_server;restart_max;log_http_file_count;log_http_number_of_files_limited;bea_home;weblogic_plugin_enabled;listenportenabled;auto_restart;autokillwfail;server_parameters;frontendhost;frontendhttpport;frontendhttpsport;log_date_pattern")
for token in m:
  print '___'+token+'___'
  cd('/Servers/'+token)
  listenAddress     = get('ListenAddress')
  listenPort        = str(get('ListenPort'))
  listenPortEnabled = str(get('ListenPortEnabled'))
  max_message_size  = str(get('MaxMessageSize'))
  tunnelingenabled  = str(get('TunnelingEnabled'))
  logintimeout	    = str(get('LoginTimeoutMillis'))
  restart_max       = str(get('RestartMax'))

  auto_restart      = str(get('AutoRestart'))
  autokillwfail     = str(get('AutoKillIfFailed'))
  server_parameters = str(get('Notes'))
  if get("KeyStores") == "CustomIdentityAndCustomTrust":
    custom_identity = '1'
  else:
    custom_identity = '0'

  custom_identity_keystore_filename = get("CustomIdentityKeyStoreFileName")
  trust_keystore_file               = get("CustomTrustKeyStoreFileName")
  weblogic_plugin_enabled           = str(get('WeblogicPluginEnabled'))

  cd('/Servers/'+token+'/SSL/'+token)
  sslListenPort                     = str(get('ListenPort'))
  sslEnabled                        = str(get('Enabled'))
  sslHostnameVerificationIgnored    = str(get('HostnameVerificationIgnored'))
  sslhostnameverifier               = str(get('HostnameVerifier'))
  two_way_ssl                       = str(get('TwoWaySSLEnabled'))
  client_certificate_enforced       = str(get('ClientCertificateEnforced'))
  jsseEnabled                       = str(get('JSSEEnabled'))
  useservercerts                    = str(get('UseServerCerts'))
  custom_identity_alias             = get("ServerPrivateKeyAlias")

  cd('/Servers/'+token+'/ServerStart/'+token)
  bea_home      = get('BeaHome')
  classpath     = get('ClassPath')
  if classpath == None:
      classpath = ''

  arguments     = get('Arguments')
  if arguments == None:
      arguments = ''

  cd('/Servers/'+token+'/WebServer/'+token)
  if get('FrontendHost'):
    frontendhost = get('FrontendHost')
  else:
    frontendhost = ''

  if get('FrontendHTTPPort'):
    frontendhttpport = get('FrontendHTTPPort')
  else:
    frontendhttpport = '0'

  if get('FrontendHTTPSPort'):
    frontendhttpsport = get('FrontendHTTPSPort')
  else:
    frontendhttpsport = '0'


  cd('/Servers/'+token+'/Log/'+token)
  logfilename                   = get('FileName')
  log_rotationtype              = get('RotationType')
  log_rotate_logon_startup      = str(get('RotateLogOnStartup'))
  log_number_of_files_limited   = str(get('NumberOfFilesLimited'))
  log_filecount                 = str(get('FileCount'))
  log_file_min_size             = str(get('FileMinSize'))
  log_redirect_stderr_to_server = str(get('RedirectStderrToServerLogEnabled'))
  log_redirect_stdout_to_server = str(get('RedirectStdoutToServerLogEnabled'))
  log_date_pattern              = get('DateFormatPattern')

  cd('/Servers/'+token+'/WebServer/'+token+'/WebServerLog/'+token)
  log_http_filename                = get('FileName')
  log_http_format                  = get('ELFFields')
  log_http_format_type             = get('LogFileFormat')
  log_http_file_count              = get('FileCount')
  log_http_number_of_files_limited = str(get('NumberOfFilesLimited'))
  print log_http_number_of_files_limited

  cd('/Servers/'+token+'/DataSource/'+token+'/DataSourceLogFile/'+token)
  log_datasource_filename          = get('FileName')

  cd('/Servers/'+token+'/DefaultFileStore/'+token)
  default_file_store = get('Directory')

  print "Querying " + token + " Machine:"

  n = ls('/Servers/'+token+'/Machine')
  machine = ''
  for token2 in n.split("drw-"):
      token2=token2.strip().lstrip().rstrip()
      if token2:
         machine = token2

  print "Querying " + token + " Cluster:"

  cluster = ''
  cluster_query = ls('/Servers/'+token+'/Cluster', returnMap = 'true')
  if cluster_query :
    for c in cluster_query :
      cluster = c[0]
      print "Cluster: "
      print cluster

  print "Adding index entry..."

  add_index_entry(f, [domain+'/'+token, listenAddress, listenPort, logintimeout, sslListenPort, sslEnabled, sslHostnameVerificationIgnored, sslhostnameverifier, two_way_ssl, client_certificate_enforced, useservercerts, machine, cluster, logfilename,log_file_min_size,log_filecount,log_rotate_logon_startup,log_rotationtype,log_number_of_files_limited, tunnelingenabled,log_http_filename,log_http_format,log_http_format_type,log_datasource_filename, classpath, arguments,jsseEnabled,domain,custom_identity,custom_identity_keystore_filename,trust_keystore_file,custom_identity_alias,default_file_store,max_message_size, log_redirect_stderr_to_server, log_redirect_stdout_to_server, restart_max, log_http_file_count,log_http_number_of_files_limited, bea_home, weblogic_plugin_enabled, listenPortEnabled,auto_restart,autokillwfail,server_parameters,frontendhost,frontendhttpport,frontendhttpsport,log_date_pattern])
  
  print "Index entry added."

f.close()
report_back_success()

