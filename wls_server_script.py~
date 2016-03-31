
#
# The functions in this file are available in all WLST sessions within the
# daemon. You can use them in all actions.
#
import re
import jarray


def report_back_success():
    print "~~~~COMMAND SUCCESFULL~~~~"


def report_back_error():
    print "Unexpected error:", sys.exc_info()[0]
    undo('true', 'y')
    stopEdit('y')
    print "~~~~COMMAND FAILED~~~~"
    raise


def report_back_error_without_undo():
    print "Unexpected error:", sys.exc_info()[0]
    print "~~~~COMMAND FAILED~~~~"
    raise


def quote(text):
    if text or text == '':
        return "\"" + str(text).replace("\"", "\"\"") + "\""
    else:
        return ""


def open_file(fields):
    f = open("/tmp/wlstScript.out", "w")
    print >>f, fields
    return f


def add_index_entry(file_handle, values):
    print >>file_handle, ";".join(map(quote, values))


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
        return True
    else:
        return False


def create_boot_properties_file(directory_path, file_name, username, password):
    server_dir = File(directory_path)
    server_dir.mkdirs()
    full_file_name = directory_path + '/' + file_name
    file_new = open(full_file_name, 'w')
    file_new.write('username=%s\n' % username)
    file_new.write('password=%s\n' % password)
    file_new.flush()
    file_new.close()
    os.system('chmod 600 ' + full_file_name)


def retrieve_target_list(wlst_name):
    cd(wlst_name)
    nn = ls('Targets', returnMap='true')
    target = []
    target_type = []
    for token_target in nn:
        target.append(token_target)
        cd(wlst_name + '/Targets/' + token_target)
        target_type.append(get('Type'))
    return target, target_type


def retrieve_virtual_target_list(wlst_name, field):
    print wlst_name
    cd(wlst_name)
    nn = ls(field, returnMap='true')
    target = []
    for token_target in nn:
        target.append(token_target)
    return target


def target_list(targets, targettypes):
    targetlist = []
    for i in range(len(targets)):
        bean = ObjectName('com.bea:Name=' + targets[i] + ',Type=' + targettypes[i])
        targetlist.append(bean)
    return jarray.array(targetlist, ObjectName)


def target_list_same_type(targets, targettype):
    targetlist = []
    for i in range(len(targets)):
        bean = ObjectName('com.bea:Name=' + targets[i] + ',Type=' + targettype)
        targetlist.append(bean)
    return jarray.array(targetlist, ObjectName)


def password_to_string(value):
    if value is None:
        return None
    else:
        string_value = ''
        for byte in value:
            string_value = string_value + chr(byte)
        return string_value


def decrypt_value(encrypted_value):
    domain_dir = get('RootDirectory')
    domain_dir_path = os.path.abspath(domain_dir)
    print weblogic.security.internal.SerializedSystemIni.getPath()
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
    key = elements.pop()
    path = '/'.join(elements)
    print path
    print key
    old_path = pwd()
    cd(path)
    key_description = man(key)
    cd(old_path)
    encrypted = re.search("\|(?:com.bea.)?encrypted : (true)\|\|", key_description) is not None
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
    if value is None:
        return
    if key_type == 'int':
        if value.strip():
            print 'Setting integer property ' + key + ' to ' + value
            set(key, int(value))
    elif key_type == 'boolean':
        if value.strip():
            print 'Setting boolean property ' + key + ' to ' + value
            if value == 'True' or value == 'true' or value == '1':
                real_value = 'true'
            else:
                real_value = 'false'
        set(key, real_value)
    elif key_type == 'float':
        if value.strip():
            print 'Setting float property ' + key + ' to ' + value
            set(key, float(value))
    elif key_type == 'array':
        if value.strip():
            print 'Setting array property ' + key + ' to ' + value
            set(key, jarray.array(value, String))
    else:
        print 'Setting generic property ' + key + ' to ' + value
        set(key, value)


def set_attribute_value(mbean_attribute, value=None, set_default=True):
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
    key_type = fields[0]
    # have default value
    default_value = fields[1]
    # defaulvalue is null
    null_value = fields[2]
    #
    # if the value is not specified set the default value if it defined
    if value:
        attribute_value = str(value)
    else:
        if not set_default:
            print "found empty value, but we will skip it because of set_default param"
            return
        print "found empty value, try to use the defaults"
        if default_value is not None:
            # assign default to value
            print 'found default value instead of empty'
            attribute_value = str(default_value)
        elif null_value == 1:
            # set None and return
            set(mbean_attribute, None)
            return
        else:
            return
    if key_type == 'int':
        # possible check min max
        if attribute_value.strip():
            print 'Setting integer property ' + mbean_attribute + ' to ' + attribute_value
            set(mbean_attribute, int(attribute_value))
    elif key_type == 'boolean':
        if attribute_value.strip():
            print 'Setting boolean property ' + mbean_attribute + ' to ' + attribute_value
            if attribute_value == 'True' or attribute_value == 'true' or attribute_value == '1':
                real_value = 'True'
            else:
                real_value = 'False'
            set(mbean_attribute, real_value)
    elif key_type == 'float':
        if attribute_value.strip():
            print 'Setting float property ' + mbean_attribute + ' to ' + attribute_value
            set(mbean_attribute, float(attribute_value))
    else:
        print 'Setting generic property ' + mbean_attribute + ' to ' + attribute_value
        set(mbean_attribute, attribute_value)


arguments = ''
weblogicUser = 'weblogic'
weblogicPassword = 'weblogic1'

use_default_value_when_empty = True

real_domain='default'

wlst_action = 'create'

name          = 'ManagedServer01'
classpath     = ''

machineName   = 'm_managed01'
bea_home      = ''

cluster_name = 'WebCluster'.strip()

logFilename                 = ''
log_http_Filename           = ''
log_http_format             = ''
log_http_format_type        = ''
log_http_file_count              = ''
log_http_number_of_files_limited = ''
log_datasource_Filename     = ''
log_file_min_size           = ''
log_filecount               = ''
log_rotate_logon_startup    = ''
log_rotationtype            = ''
log_number_of_files_limited = ''
log_redirect_stderr_to_server = ''
log_redirect_stdout_to_server = ''
log_date_pattern              = ''

restart_max       = ''
listenAddress     = '192.168.33.11'
listenPort        = '7001'
listenPortEnabled = '1'
sslEnabled        = ''
sslHostnameVerificationIgnored = ''
sslhostnameverifier = ''
two_way_ssl       = ''
client_certificate_enforced = ''
sslListenPort     = ''
useservercerts = ''


logintimeout      = ''
jsseenabled       = ''
tunnelingenabled  = ''

custom_identity                        = ''
custom_identity_keystore_filename      = ''
custom_identity_keystore_passphrase    = ''
custom_identity_alias                  = ''
custom_identity_privatekey_passphrase  = ''
trust_keystore_file                    = ''
trust_keystore_passphrase              = ''

default_file_store                     = ''
max_message_size                       = ''
weblogic_plugin_enabled                = ''
auto_restart                           = ''
autokillwfail                          = ''

server_parameters		       = 'None'

frontend_host                  = ''
frontend_http_port             = '0'
frontend_https_port            = '0'

edit()
startEdit()

try:

    cd('/')
    AdminServerName = get('AdminServerName')
    if name == AdminServerName:
      raise "Cannot create a new AdminServer, its not allowed"

    cmo.createServer(name)

    cd('/Servers/'+name)
    set('Machine',getMBean('/Machines/'+machineName))

    if cluster_name :
      cmo.setCluster(getMBean('/Clusters/'+cluster_name))

    print "Change Notes"
    if server_parameters and server_parameters != 'None':
      set_attribute_value('Notes', server_parameters, use_default_value_when_empty)

    print "Change listenAddress"
    if listenAddress and not listenAddress.isspace():
      set_attribute_value('ListenAddress', listenAddress, use_default_value_when_empty)

    set_attribute_value('ListenPort', listenPort)
    if listenPortEnabled and listenPortEnabled != '-1':
      set_attribute_value('ListenPortEnabled', listenPortEnabled, use_default_value_when_empty)

    set_attribute_value('LoginTimeoutMillis', logintimeout, use_default_value_when_empty)
    set_attribute_value('MaxMessageSize', max_message_size, use_default_value_when_empty)
    set_attribute_value('RestartMax', restart_max, use_default_value_when_empty)

    if classpath:
      set('ServerStart/'+name+'/ClassPath', classpath)

    if bea_home:
      set('ServerStart/'+name+'/BeaHome', bea_home)

    if arguments:
      set('ServerStart/'+name+'/Arguments', arguments)

    set_attribute_value('TunnelingEnabled', tunnelingenabled, use_default_value_when_empty)
    set_attribute_value('WeblogicPluginEnabled', weblogic_plugin_enabled, use_default_value_when_empty)

    if custom_identity == '1':
      set_attribute_value('KeyStores', 'CustomIdentityAndCustomTrust', use_default_value_when_empty)
      set_attribute_value('CustomIdentityKeyStoreFileName', custom_identity_keystore_filename, use_default_value_when_empty)
      set_attribute_value('CustomIdentityKeyStorePassPhrase', custom_identity_keystore_passphrase, use_default_value_when_empty)
      set_attribute_value('CustomTrustKeyStoreFileName', trust_keystore_file, use_default_value_when_empty)
      set_attribute_value('CustomTrustKeyStorePassPhrase', trust_keystore_passphrase, use_default_value_when_empty)

      cd('SSL/'+name)
      set_attribute_value('ServerPrivateKeyAlias', custom_identity_alias, use_default_value_when_empty)
      set_attribute_value('ServerPrivateKeyPassPhrase', custom_identity_privatekey_passphrase, use_default_value_when_empty)

    if custom_identity == '0':
      set_attribute_value('KeyStores', 'DemoIdentityAndDemoTrust', use_default_value_when_empty)

    cd('/Servers/'+name)
    set_attribute_value('AutoRestart', auto_restart, use_default_value_when_empty)
    set_attribute_value('AutoKillIfFailed', autokillwfail, use_default_value_when_empty)

    cd('/Servers/'+name+'/WebServer/'+name)

    set_attribute_value('FrontendHost', frontend_host, use_default_value_when_empty)
    set_attribute_value('FrontendHTTPPort', frontend_http_port, use_default_value_when_empty)
    set_attribute_value('FrontendHTTPSPort', frontend_https_port, use_default_value_when_empty)

    print "Change SSL"
    cd('/Servers/'+name+'/SSL/'+name)

    if sslEnabled and sslEnabled != '-1':
      set_attribute_value('Enabled', sslEnabled, use_default_value_when_empty)
    if jsseenabled and jsseenabled != '-1':
      set_attribute_value('JSSEEnabled', jsseenabled, use_default_value_when_empty)
    if sslHostnameVerificationIgnored and sslHostnameVerificationIgnored != '-1':
      set_attribute_value('HostnameVerificationIgnored', sslHostnameVerificationIgnored, use_default_value_when_empty)
      if sslHostnameVerificationIgnored == '0' and sslhostnameverifier:
        set_attribute_value('HostnameVerifier', sslhostnameverifier, use_default_value_when_empty)

    set_attribute_value('TwoWaySSLEnabled', two_way_ssl, use_default_value_when_empty)
    set_attribute_value('ClientCertificateEnforced', client_certificate_enforced, use_default_value_when_empty)
    set_attribute_value('ListenPort', sslListenPort, use_default_value_when_empty)
    set_attribute_value('UseServerCerts', useservercerts, use_default_value_when_empty)

    cd('/Servers/'+name+'/Log/'+name)
    set_attribute_value('FileName', logFilename, use_default_value_when_empty)
    set_attribute_value('RotationType', log_rotationtype, use_default_value_when_empty)
    set_attribute_value('RotateLogOnStartup', log_rotate_logon_startup, use_default_value_when_empty)
    set_attribute_value('FileCount', log_filecount, use_default_value_when_empty)
    set_attribute_value('NumberOfFilesLimited', log_number_of_files_limited, use_default_value_when_empty)
    set_attribute_value('FileMinSize', log_file_min_size, use_default_value_when_empty)
    set_attribute_value('DateFormatPattern', log_date_pattern, use_default_value_when_empty)
    set_attribute_value('RedirectStderrToServerLogEnabled', log_redirect_stderr_to_server, use_default_value_when_empty)
    set_attribute_value('RedirectStdoutToServerLogEnabled', log_redirect_stdout_to_server, use_default_value_when_empty)

    print "web server log: " + name
    cd('/Servers/'+name+'/WebServer/'+name+'/WebServerLog/'+name)
    set_attribute_value('NumberOfFilesLimited', log_http_number_of_files_limited, use_default_value_when_empty)
    set_attribute_value('FileCount', log_http_file_count, use_default_value_when_empty)
    set_attribute_value('FileName', log_http_Filename, use_default_value_when_empty)
    set_attribute_value('RotationType', log_rotationtype, use_default_value_when_empty)
    set_attribute_value('RotateLogOnStartup', log_rotate_logon_startup, use_default_value_when_empty)
    set_attribute_value('FileMinSize', log_file_min_size, use_default_value_when_empty)
    set_attribute_value('LogFileFormat', log_http_format_type, use_default_value_when_empty)
    set_attribute_value('ELFFields', log_http_format, use_default_value_when_empty)


    print "datasource server log: " + name
    cd('/Servers/'+name+'/DataSource/'+name+'/DataSourceLogFile/'+name)
    set_attribute_value('FileName', log_datasource_Filename, use_default_value_when_empty)
    set_attribute_value('RotationType', log_rotationtype, use_default_value_when_empty)
    set_attribute_value('RotateLogOnStartup', log_rotate_logon_startup, use_default_value_when_empty)
    set_attribute_value('FileCount', log_filecount, use_default_value_when_empty)
    set_attribute_value('NumberOfFilesLimited', log_number_of_files_limited, use_default_value_when_empty)
    set_attribute_value('FileMinSize', log_file_min_size, use_default_value_when_empty)

    if default_file_store:
      cd('/Servers/'+name+'/DefaultFileStore/'+name)
      set_attribute_value('Directory', default_file_store, use_default_value_when_empty)

    cd('/')
    DOMAIN_PATH = get('RootDirectory')

    create_boot_properties_file(DOMAIN_PATH+'/servers/'+name+'/security','boot.properties',weblogicUser,weblogicPassword)
    save()
    activate()
    report_back_success()


except:
    report_back_error()

