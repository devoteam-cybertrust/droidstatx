import hashlib
from androguard.misc import AnalyzeAPK
from androguard.core.bytecodes import apk
from androguard.core.bytecodes import dvm
from androguard.core.analysis import analysis
import re
from subprocess import * #check_output
from SmaliChecks import *
import os
from Configuration import *
from IntentFilter import *

class App:

  a=""
  d=""
  dx=""
  xml = ""
  manifest=""
  application=""
  exportedActivities = []
  intentFilterList = {}
  componentPermissionList = {}
  activitiesWithExcludeFromRecents=[]
  activitiesExtendPreferencesWithValidate = []
  activitiesExtendPreferencesWithoutValidate = []
  activitiesWithoutFlagSecure = []
  exportedReceivers = []
  exportedProviders = []
  exportedServices = []
  permissions = []
  secretCodes = []
  libs = []
  assemblies = []
  assets = []
  cordova = []
  rawResources = []
  dexFiles = []
  otherFiles  =[]
  cordovaPlugins = []
  isAppXamarin = False
  xamarinMKBundled = False
  xamarinBundledFile = ""
  isAppCordova = False
  isAppOutsystems = False
  hasNetworkSecurityConfig = False
  minSDKVersion= ""
  targetSDKVersion = ""
  versionCode= ""
  versionName= ""
  codeNames={"3":"Cupcake 1.5","4":"Donut 1.6","5":"Eclair 2.0","6":"Eclair 2.0.1","7":"Eclair 2.1","8":"Froyo 2.2.x","9":"Gingerbread 2.3 - 2.3.2","10":"Gingerbread 2.3.3 - 2.3.7","11":"Honeycomb 3.0","12":"Honeycomb 3.1","13":"Honeycomb 3.2.x","14":"Ice Cream Sandswich 4.0.1 - 4.0.2","15":"Ice Cream Sandswich 4.0.3 - 4.0.4","16":"Jelly Bean 4.1.x","17":"Jelly Bean 4.2.x","18":"Jelly Bean 4.3.x","19":"KitKat 4.4 - 4.4.4","21":"Lolipop 5.0","22":"Lolipop 5.1","23":"Marshmallow 6.0","24":"Nougat 7.0","25":"Nougat 7.1","26":"Oreo 8.0","27":"Oreo 8.1.0"}
  sha256 = ""
  packageName = ""
  debuggable = False
  allowBackup = False
  certificate =""
  NS_ANDROID_URI = "http://schemas.android.com/apk/res/android"
  NS_ANDROID = '{http://schemas.android.com/apk/res/android}'
  baksmaliPaths=[]
  smaliChecks = None
  configuration = Configuration()

  def __init__(self,apkFile):
    self.sha256 = self.sha256CheckSum(apkFile)
    print "[-]Parsing APK"
    self.a = apk.APK(apkFile)
    print "[-]Baksmaling DEX files"
    self.bakmali(apkFile)
    self.manifest = self.a.get_android_manifest_axml().get_xml_obj()
    self.application = self.manifest.findall("application")[0]
    print "[+]Gathering Information"
    self.extractActivitiesWithExcludeFromRecents()
    self.extractActivitiesWithoutSecureFlag()
    print "   [-]Package Properties"
    self.extractPackageProperties()
    print "   [-]Exported Components"
    self.extractExportedComponents()
    print "   [-]Permissions"
    self.extractPermissions()
    print "   [-]Files"
    self.extractFiles()

  #Return the Android Code Name for the particular Api Level.

  def getCodeName(self,apiLevel):
      return self.codeNames[apiLevel]

  #Return the SHA256 of the APK file.

  def sha256CheckSum(self,filename):
    f = open(filename, 'rb')
    contents = f.read()
    return hashlib.sha256(contents).hexdigest()

  #Extract package properties such as the minSDKVersion,PackageName,VersionName,VersionCode,isDebuggable,allowBackup

  def extractPackageProperties(self):
    usesSDK = self.manifest.findall("uses-sdk")
    self.minSDKVersion = self.a.get_min_sdk_version()
    self.targetSDKVersion = self.a.get_target_sdk_version()
    self.packageName = self.a.get_package()
    self.versionName = self.a.get_androidversion_name()
    self.versionCode = self.a.get_androidversion_code()
    if self.application.get(self.NS_ANDROID+"debuggable") == 'true':
      self.debuggable = True
    if self.application.get(self.NS_ANDROID+"allowBackup") == 'true':
      self.allowBackup = True
    elif self.application.get(self.NS_ANDROID+"allowBackup") == 'false':
      self.allowBackup = False
    else:
        self.allowBackup = True
    if self.application.get(self.NS_ANDROID+"networkSecurityConfig") is not None:
      self.hasNetworkSecurityConfig = True

  # Create the list of permissions used by the package

  def extractPermissions(self):
    for permission in self.a.get_permissions():
      self.permissions.append(str(permission))

  def extractCertificate(self):
    self.certificate = self.a.get_signature_name()

  #Check for the presence of a SECRET_CODE in the object and add it to a global list of objects with SECRET_CODEs.

  def checkForSecretCodes(self,object):
    intentFilters = object.findall("intent-filter")
    for intentFilter in intentFilters:
      if len(intentFilter.findall("data")) > 0:
        datas = intentFilter.findall("data")
        for data in datas:
          if data.get(self.NS_ANDROID+"scheme") == "android_secret_code":
            self.secretCodes.append(data.get(self.NS_ANDROID+"host"))

  #Create a global list of activities with the excludeFromRecentes attribute

  def extractActivitiesWithExcludeFromRecents(self):
    for activity in self.application.findall("activity"):
      if activity.get(self.NS_ANDROID+"excludeFromRecents") == 'true':
        self.activitiesWithExcludeFromRecents.append(activity)

  #Return the ProtectionLevel of a particular Permission

  def determinePermissionProtectionLevel(self,targetPermission):
    for permission in self.manifest.findall("permission"):
      if permission.get(self.NS_ANDROID+"name") == targetPermission:
        print permission.get(self.NS_ANDROID+"protectionLevel")
    return ""

  # Add the extracted permission of a particular component to a global list indexed by the component name.

  def extractComponentPermission(self,component):
    if component.get(self.NS_ANDROID+"permission") != None:
      self.componentPermissionList[component.get(self.NS_ANDROID+"name")] = component.get(self.NS_ANDROID+"permission")

  #Create a global list with that particular object intent-filters indexed to the component name.

  def extractIntentFilters(self,filters,obj):
    filterList = []
    name = obj.get(self.NS_ANDROID+"name")
    filters = obj.findall("intent-filter")
    for filter in filters:
      intentFilter = IntentFilter()
      if len(filter.findall("action")) > 0:
        for action in filter.findall("action"):
          intentFilter.addAction(action.get(self.NS_ANDROID+"name"))
      if len(filter.findall("category")) > 0:
        for category in filter.findall("category"):
          intentFilter.addCategory(category.get(self.NS_ANDROID+"name"))
      if len(filter.findall("data")) > 0:
        for data in filter.findall("data"):
          if data.get(self.NS_ANDROID+"scheme") is not None:
            intentFilter.addData("scheme:"+data.get(self.NS_ANDROID+"scheme"))
          if data.get(self.NS_ANDROID+"host") is not None:
            intentFilter.addData("host:"+data.get(self.NS_ANDROID+"host"))
          if data.get(self.NS_ANDROID+"port") is not None:
            intentFilter.addData("port:"+data.get(self.NS_ANDROID+"port"))
          if data.get(self.NS_ANDROID+"path") is not None:
            intentFilter.addData("path:"+data.get(self.NS_ANDROID+"path"))
          if data.get(self.NS_ANDROID+"pathPattern") is not None:
            intentFilter.addData("pathPattern:"+data.get(self.NS_ANDROID+"pathPattern"))
          if data.get(self.NS_ANDROID+"pathPrefix") is not None:
            intentFilter.addData("pathPrefix:"+data.get(self.NS_ANDROID+"pathPrefix"))
          if data.get(self.NS_ANDROID+"mimeType") is not None:
            intentFilter.addData("mimeType:"+data.get(self.NS_ANDROID+"mimeType"))
      filterList.append(intentFilter)
    self.intentFilterList[name] = filterList


  # Determine exported Activities taking into account the existence of exported attribute or the presence of intent-filters and also check for presence of secretCode and if vulnerable to Fragment Injection
  # Check if any of the activities (exported or not) have any SECRET_CODE configured.

  def extractExportedActivities(self):
    for activity in self.application.findall("activity"):
      activityName = activity.get(self.NS_ANDROID+"name")
      self.checkForSecretCodes(activity)
      if len(activity.findall("intent-filter")) > 0:
        filters = activity.findall("intent-filter")
	self.extractIntentFilters(filters, activity)
      if activity.get(self.NS_ANDROID+"exported") == 'true':
        self.extractComponentPermission(activity)
        if self.smaliChecks.doesActivityExtendsPreferenceActivity(activityName) == True:
          if self.smaliChecks.doesPreferenceActivityHasValidFragmentCheck(activityName) == True:
            try:
              activityName.encode("ascii")
            except UnicodeEncodeError,e:
              activityName = activityName.encode('ascii','xmlcharrefreplace')
            self.activitiesExtendPreferencesWithValidate.append(activityName)
          else:
            try:
              activityName.encode("ascii")
            except UnicodeEncodeError,e:
              activityName = activityName.encode('ascii','xmlcharrefreplace')
            self.activitiesExtendPreferencesWithoutValidateValidate.append(activityName)
        self.exportedActivities.append(activityName)
        if "com.outsystems.android" in activityName:
          self.isAppOutsystems = True
      elif activity.get(self.NS_ANDROID+"exported") != 'false':
        if len(activity.findall("intent-filter")) > 0:
          self.extractIntentFilters(filters, activity)
          self.extractComponentPermission(activity)
          self.exportedActivities.append(activityName)
          if self.smaliChecks.doesActivityExtendsPreferenceActivity(activityName) == True:
            if self.smaliChecks.doesPreferenceActivityHasValidFragmentCheck(activityName) == True:
              try:
                activityName.encode("ascii")
              except UnicodeEncodeError, e:
                activityName = activityName.encode('ascii', 'xmlcharrefreplace')
              self.activitiesExtendPreferencesWithValidate.append(activityName)
            else:
              try:
                activityName.encode("ascii")
              except UnicodeEncodeError, e:
                activityName = activityName.encode('ascii', 'xmlcharrefreplace')
              self.activitiesExtendPreferencesWithoutValidate.append(activityName)
          if "com.outsystems.android" in activityName:
            self.isAppOutsystems = True

  #Determine exported Broadcast Receivers taking into account the existence of exported attribute or the presence of intent-filters

  def extractExportedReceivers(self):
    for receiver in self.application.findall("receiver"):
      receiverName = receiver.get(self.NS_ANDROID+"name")
      self.checkForSecretCodes(receiver)
      if receiver.get(self.NS_ANDROID+"exported") == 'true':
        if len(receiver.findall("intent-filter")) > 0:
          filters = receiver.findall("intent-filter")
          self.extractIntentFilters(filters, receiver)
          self.extractComponentPermission(receiver)
        self.exportedReceivers.append(receiverName)
      elif receiver.get(self.NS_ANDROID+"exported") != 'false':
        if len(receiver.findall("intent-filter")) > 0:
          filters = receiver.findall("intent-filter")
          self.extractIntentFilters(filters, receiver)
          self.extractComponentPermission(receiver)
          self.exportedReceivers.append(receiverName)


  # Determine exported Content Providers taking into account the existence of exported attribute or without the attributes, under API 16 they are exported by default

  def extractExportedProviders(self):
    for provider in self.application.findall("provider"):
      providerName = provider.get(self.NS_ANDROID+"name")
      self.checkForSecretCodes(provider)
      if provider.get(self.NS_ANDROID+"exported") == 'true':
        self.exportedProviders.append(providerName)
      elif provider.get(self.NS_ANDROID+"exported") != 'false':
        if self.minSDKVersion <=16:
          self.extractComponentPermission(provider)
          self.exportedProviders.append(providerName+" * In devices <= API 16 (Jelly Bean 4.1.x)")

  # Determine exported Services taking into account the existence of exported attribute or the presence of intent-filters

  def extractExportedServices(self):
    for service in self.application.findall("service"):
      serviceName = service.get(self.NS_ANDROID+"name")
      self.checkForSecretCodes(service)
      if service.get(self.NS_ANDROID+"exported") == 'true':
        if len(service.findall("intent-filter")) > 0:
          filters = service.findall("intent-filter")
          self.extractComponentPermission(service)
          self.extractIntentFilters(filters, service)
        self.exportedServices.append(serviceName)
      elif service.get(self.NS_ANDROID+"exported") != 'false':
        if len(service.findall("intent-filter")) > 0:
          filters = service.findall("intent-filter")
          self.extractIntentFilters(filters, service)
          self.extractComponentPermission(service)
          self.exportedServices.append(serviceName)

  #Run the functions that extract the exported components.

  def extractExportedComponents(self):
    self.extractExportedActivities()
    self.extractExportedReceivers()
    self.extractExportedProviders()
    self.extractExportedServices()

  #Return the app permissions global list

  def getPermissions(self):
    return self.permissions

  #Return the exported activities global list

  def getExportedActivities(self):
    return self.exportedActivities

  #Return the the exported broadcast receivers global list

  def getExportedReceivers(self):
    return self.exportedReceivers

  #Return the exported content providers global list

  def getExportedProviders(self):
    return self.exportedProviders

  #Return the exported services global list

  def getExportedServices(self):
    return self.exportedServices

  #Return the app package name

  def getPackageName(self):
    return self.packageName

  #Return the app minSDKVersion

  def getMinSDKVersion(self):
    return self.minSDKVersion

  # Return the app targetSDKVersion

  def getTargetSDKVersion(self):
    return self.targetSDKVersion

  #Return the app versionName

  def getVersionName(self):
    return self.versionName

  #Return the app versionCode

  def getVersionCode(self):
    return self.versionCode

  #Return the APK SHA256

  def getSHA256(self):
    return self.sha256

  #Return the permission defined in the particular component.

  def getComponentPermission(self,name):
    try:
      return self.componentPermissionList[name]
    except:
      return ""

  def isCordova(self):
    if self.isAppCordova == True:
      return "Yes"
    else:
      return "No"

  def isXamarin(self):
    if self.isAppXamarin == True:
      return "Yes"
    else:
      return "No"

  def isXamarinBundled(self):
    if self.xamarinMKBundled == True:
      return "Yes"
    else:
      return "No"

  def isOutsystems(self):
    if self.isAppOutsystems == True:
      return "Yes"
    else:
      return "No"

  def isDebuggable(self):
    if self.debuggable == True:
      return "Yes"
    else:
      return "No"

  def isBackupEnabled(self):
    if self.allowBackup == True:
      return "Yes"
    else:
      return "No"

  def hasNetworkSecurityConfig(self):
    return self.hasNetworkSecurityConfig

  def isMultiDex(self):
    if len(self.getDexFiles()) > 1:
        return "Yes"
    else:
        return "No"

  def getAssets(self):
    return self.assets

  def getCordovaFiles(self):
    return self.cordova

  def getRawResources(self):
    return self.rawResources

  def getLibs(self):
    return self.libs

  def getOtherFiles(self):
      return self.otherFiles

  def getXamarinAssemblies(self):
    return self.assemblies

  def getDexFiles(self):
      return self.dexFiles

  def getSecretCodes(self):
      return self.secretCodes

  def getIntentFiltersList(self):
    return self.intentFilterList

  #Determine if path is in the exclude paths configured in the config file.

  def isInExclusions(self,f):
    exclusions = self.configuration.getFileExclusions().replace("\"","").split(",")
    for extension in exclusions:
      if extension in f:
        return True
    return False

  # Create a list of files, organized in several types and while doing it, by the existence of certain files, determine
  # if the app is a Cordova or Xamarin app.

  def extractFiles(self):
    files = self.a.get_files()
    try:
      for f in files:
        if self.isInExclusions(f) == False :
          try:
            f.encode("ascii")
          except UnicodeEncodeError, e:
            f = f.encode('ascii', 'xmlcharrefreplace')
          if "assets/www/" in f:
            if "assets/www/cordova.js" in f:
              self.isAppCordova = True
            if "assets/www/plugins/" in f:
              beginPos = f.find("/plugins/")+9
              endPos = f.find("/",beginPos)
              item = f[beginPos:endPos]
              self.cordovaPlugins.append(item) if item not in self.cordovaPlugins else None
            self.cordova.append(f)
          elif f[0:4] == "lib/":
            self.libs.append(f)
            if 'libmonodroid_bundle_app.so' in f:
              self.isAppXamarin = True
              self.xamarinMKBundled = True
              self.xamarinBundledFile = f
              print "[-]Extracting Dll's from bundled lib."
              self.unbundleXamarinDlls()
          elif f[0:11] == "assemblies/" in f:
            self.assemblies.append(f)
            if 'Xamarin.' in f and self.isAppXamarin == False:
              self.isAppXamarin = True
          elif "assets/" in f:
            self.assets.append(f)
          elif "res/raw/" in f:
            self.rawResources.append(f)
          elif ".dex" in f:
            self.dexFiles.append(f)
          else:
            self.otherFiles.append(f)
    except UnicodeDecodeError,e:
      pass
  # Create a global list of activities that do not have the FLAG_SECURE or the excludeFromRecents attribute set.

  def extractActivitiesWithoutSecureFlag(self):
    activitiesWithoutSecureFlag = []
    for activity in self.a.get_activities():
      if self.smaliChecks.doesActivityHasFlagSecure(activity) == False and activity not in self.getActivitiesWithExcludeFromRecents():
        try:
          activity.encode("ascii")
        except UnicodeEncodeError, e:
          activity = activity.encode('ascii', 'xmlcharrefreplace')
        self.activitiesWithoutFlagSecure.append(activity)

  def getActivitiesWithExcludeFromRecents(self):
    return self.activitiesWithExcludeFromRecents

  def getActivitiesWithoutSecureFlag(self):
    return self.activitiesWithoutFlagSecure

  def getActivitiesExtendPreferencesWithValidate(self):
    return self.activitiesExtendPreferencesWithValidate

  def getActivitiesExtendPreferencesWithoutValidate(self):
    return self.activitiesExtendPreferencesWithoutValidate

  def getCordovaPlugins(self):
    return self.cordovaPlugins

  #Run apktool on the package with the options
  #  d : Decompile
  # -b : Don't write out debug info
  # -f : Force rewrite
  # -o : Output folder

  def bakmali(self,apkFile):
      cwd = os.path.dirname(os.path.realpath(__file__))
      apktool = Popen(["java","-jar",cwd+"/apktool.jar", "d","-b", "-f","--frame-path","/tmp/", apkFile, "-o", cwd+"/output_apktool/"+self.a.get_package()+"_"+self.a.get_androidversion_code()+"/"], stdout=PIPE)
      output = apktool.communicate()[0]
      numberOfDexFiles = output.count("Baksmaling")
      if numberOfDexFiles > 1:
        path = cwd+"/output_apktool/" + self.a.get_package()+"_"+self.a.get_androidversion_code()+ "/smali/"
        self.baksmaliPaths.append(path)
        for i in range (1,numberOfDexFiles):
          path=cwd+"/output_apktool/"+self.a.get_package()+"_"+self.a.get_androidversion_code()+"/smali_classes"+str(i+1)+"/"
          self.baksmaliPaths.append(path)
      else:
        path = cwd+"/output_apktool/" + self.a.get_package()+"_"+self.a.get_androidversion_code() + "/smali/"
        self.baksmaliPaths.append(path)
      self.smaliChecks = SmaliChecks(self.baksmaliPaths)

  def unbundleXamarinDlls(self):
    cwd = os.path.dirname(os.path.realpath(__file__))
    bundledFile = cwd+"/output_apktool/" + self.a.get_package()+"_"+self.a.get_androidversion_code()+"/"+self.xamarinBundledFile
    command = ["objdump", "-T", "-x", "-j", ".rodata",bundledFile]
    objdump = Popen(command, stdout=PIPE)
    sed = Popen(["sed", "-e", "1,/DYNAMIC SYMBOL TABLE/ d"], stdin=objdump.stdout, stdout=PIPE)
    dlls = []
    for line in sed.stdout:
      if len(line.strip().split()) > 0:
        dlls.append(line.strip().split())
    files = []
    for dll in dlls:
      if "config" not in dll[6]:
        skip = int(dll[0], 16)
        length = int(dll[4], 16)
        name = dll[6].replace("assembly_data_","").replace("_dll",".dll") + ".gz"
        packageFolder = self.a.get_package()+"_"+self.a.get_androidversion_code()
        if not os.path.exists(cwd + "/output_dlls/"+packageFolder):
          os.makedirs(cwd + "/output_dlls/"+packageFolder)
        command = ["dd", "iflag=skip_bytes", "bs=1",
                   "if="+bundledFile,
                   "skip=" + str(skip), "count=" + str(length),
                   "of="+cwd+"/output_dlls/"+packageFolder+"/" + name]
        files.append(cwd+"/output_dlls/"+packageFolder+"/" + name)
        dd = Popen(command, stderr=PIPE).wait()
    for f in files:
      Popen(["gzip","-d","-f",f], stdout=PIPE).wait()