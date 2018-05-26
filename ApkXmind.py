import xmind
from xmind.core import workbook,saver
from xmind.core.topic import TopicElement
from Configuration import *
from datetime import datetime
import time

class ApkXmind:

    app = ""
    workbook = ""
    sheet = ""
    configuration = Configuration()

    def __init__(self ,app):
        versionAlreadyExists = False
        self.app = app
        cwd = os.path.dirname(os.path.realpath(__file__))+"/output_xmind/"
        self.workbook = xmind.load(cwd+app.getPackageName( ) +".xmind")
	print "[-]Generating Xmind"
        if len(self.workbook.getSheets()) == 1:
            if self.workbook.getPrimarySheet().getTitle() == None:
                self.sheet = self.workbook.getPrimarySheet()
                self.sheet.setTitle(app.getVersionCode())
            else:
                self.sheet = self.workbook.createSheet()
                self.sheet.setTitle(app.getVersionCode())
                self.workbook.addSheet(self.sheet)
        else:
            self.sheet = self.workbook.createSheet()
            self.sheet.setTitle(app.getVersionCode())
            self.workbook.addSheet(self.sheet)
        rootTopic =self.sheet.getRootTopic()
        rootTopic.setTitle(app.getPackageName())
        rootTopic.setTopicStructure(self.configuration.geXmindTopicStructure())
        self.createTopics()
        self.save()

    def getRootTopic(self):
        return self.sheet.getRootTopic()

    def createTopics(self):


        informationGatheringTopic = TopicElement()
        informationGatheringTopic.setTitle("Information Gathering")

        methodologyTopic = TopicElement()
        methodologyTopic.setTitle("Methodology")


        # Properties Topic

        topicElement = TopicElement()
        topicElement.setTitle("Properties")
        informationGatheringTopic.addSubTopic(topicElement)
        subtopics = ["Version Name" ,"Version Code" ,"SHA 256" ,"Minimum SDK Version","Target SDK Version" ,"Xamarin" ,"Cordova"
                     ,"Outsystems" ,"Backup Enabled" ,"Multiple Dex Classes" ,"Secret Codes"]
        self.createSubTopics(informationGatheringTopic.getSubTopicByIndex(0) ,subtopics)
        topicElement = TopicElement()
        topicElement.setTitle(self.app.getVersionName())
        informationGatheringTopic.getSubTopicByIndex(0).getSubTopicByIndex(0).addSubTopic(topicElement)
        topicElement = TopicElement()
        topicElement.setTitle(self.app.getVersionCode())
        informationGatheringTopic.getSubTopicByIndex(0).getSubTopicByIndex(1).addSubTopic(topicElement)
        topicElement = TopicElement()
        topicElement.setTitle(self.app.getSHA256())
        informationGatheringTopic.getSubTopicByIndex(0).getSubTopicByIndex(2).addSubTopic(topicElement)
        topicElement = TopicElement()
        topicElement.setTitle \
            (self.app.getMinSDKVersion( ) +" ( " +self.app.getCodeName(self.app.getMinSDKVersion() ) +")")
        informationGatheringTopic.getSubTopicByIndex(0).getSubTopicByIndex(3).addSubTopic(topicElement)

        topicElement = TopicElement()
        topicElement.setTitle \
            (self.app.getTargetSDKVersion() + " ( " + self.app.getCodeName(self.app.getTargetSDKVersion()) + ")")
        informationGatheringTopic.getSubTopicByIndex(0).getSubTopicByIndex(4).addSubTopic(topicElement)

        topicElement = TopicElement()
        topicElement.setTitle(self.app.isXamarin())
        if self.app.isXamarin() == "Yes":
            bundledTopic = TopicElement()
            bundledTopic.setTitle("Bundled?")
            bundledValue = TopicElement()
            bundledValue.setTitle(self.app.isXamarinBundled())
            bundledTopic.addSubTopic(bundledValue)
            topicElement.addSubTopic(bundledTopic)
        informationGatheringTopic.getSubTopicByIndex(0).getSubTopicByIndex(5).addSubTopic(topicElement)
        topicElement = TopicElement()
        topicElement.setTitle(self.app.isCordova())
        if (self.app.isCordova() == "Yes"):
            if (len(self.app.getCordovaPlugins())) > 0:
                cordovaPluginsTopic = TopicElement()
                cordovaPluginsTopic.setTitle("Plugins")
                self.createSubTopics(cordovaPluginsTopic,self.app.getCordovaPlugins())
                topicElement.addSubTopic(cordovaPluginsTopic)
        informationGatheringTopic.getSubTopicByIndex(0).getSubTopicByIndex(6).addSubTopic(topicElement)
        topicElement = TopicElement()
        topicElement.setTitle(self.app.isOutsystems())
        informationGatheringTopic.getSubTopicByIndex(0).getSubTopicByIndex(7).addSubTopic(topicElement)
        topicElement = TopicElement()
        topicElement = TopicElement()
        topicElement.setTitle(self.app.isBackupEnabled())
        informationGatheringTopic.getSubTopicByIndex(0).getSubTopicByIndex(8).addSubTopic(topicElement)
        topicElement = TopicElement()
        topicElement.setTitle(self.app.isMultiDex())
        informationGatheringTopic.getSubTopicByIndex(0).getSubTopicByIndex(9).addSubTopic(topicElement)
        topicElement = TopicElement()
        if len(self.app.getSecretCodes()) >0:
            self.createSubTopics(topicElement, self.app.getSecretCodes())
            informationGatheringTopic.getSubTopicByIndex(0).getSubTopicByIndex(10).addSubTopic(topicElement)
        else:
            topicElement.setTitle("No")
            informationGatheringTopic.getSubTopicByIndex(0).getSubTopicByIndex(10).addSubTopic(topicElement)

        # Permissions Topic

        topicElement = TopicElement()
        topicElement.setTitle("Permissions")
        informationGatheringTopic.addSubTopic(topicElement)
        self.createSubTopics(informationGatheringTopic.getSubTopicByIndex(1) ,self.app.getPermissions())
        if len(self.app.getPermissions()) > self.configuration.getXmindTopipFoldAt():
            topicElement.setFolded()


        # Exported Components Topic

        topicElement = TopicElement()
        topicElement.setTitle("Exported Components")
        informationGatheringTopic.addSubTopic(topicElement)
        subtopics = ["Activities" ,"Broadcast Receivers" ,"Content Providers" ,"Services"]
        self.createSubTopics(informationGatheringTopic.getSubTopicByIndex(2) ,subtopics)
        for activity in self.app.getExportedActivities():
            topicElement = TopicElement()
            topicElement.setTitle(activity)
            if self.app.getComponentPermission(activity) != "":
                permissionTopic = TopicElement()
                permissionTopic.setTitle("Permission: "+self.app.getComponentPermission(activity))
                topicElement.addSubTopic(permissionTopic)
            try:
	        filters = self.app.getIntentFiltersList()[activity]
	        i = 1
	        for filter in filters:
	            intentTopic = TopicElement()
	            intentTopic.setTitle("Intent Filter "+str(i))
	            i+=1
	            action = TopicElement()
	            action.setTitle("Action")
	            self.createSubTopics(action, filter.getActionList())
	            category = TopicElement()
	            category.setTitle("Categories")
	            self.createSubTopics(category,filter.getCategoryList())
	            data = TopicElement()
	            data.setTitle("Data")
	            self.createSubTopics(data, filter.getDataList())
	            intentTopic.addSubTopic(action)
	            intentTopic.addSubTopic(category)
	            intentTopic.addSubTopic(data)
	            intentTopic.setFolded()
	            topicElement.addSubTopic(intentTopic)
            except:
                pass
            informationGatheringTopic.getSubTopicByIndex(2).getSubTopicByIndex(0).addSubTopic(topicElement)
        if len(self.app.getExportedActivities()) > self.configuration.getXmindTopipFoldAt():
            informationGatheringTopic.getSubTopicByIndex(2).getSubTopicByIndex(0).setFolded()
        for receiver in self.app.getExportedReceivers():
            topicElement = TopicElement()
            topicElement.setTitle(receiver)
            if self.app.getComponentPermission(receiver) != "":
                permissionTopic = TopicElement()
                permissionTopic.setTitle("Permission: "+self.app.getComponentPermission(receiver))
                topicElement.addSubTopic(permissionTopic)
            try:
                filters = self.app.getIntentFiltersList()[receiver]
                i = 1
                for filter in filters:
                    intentTopic = TopicElement()
                    intentTopic.setTitle("Intent Filter " + str(i))
                    i += 1
                    action = TopicElement()
                    action.setTitle("Action")
                    self.createSubTopics(action, filter.getActionList())
                    category = TopicElement()
                    category.setTitle("Categories")
                    self.createSubTopics(category, filter.getCategoryList())
                    data = TopicElement()
                    data.setTitle("Data")
                    self.createSubTopics(data, filter.getDataList())
                    intentTopic.addSubTopic(action)
                    intentTopic.addSubTopic(category)
                    intentTopic.addSubTopic(data)
                    intentTopic.setFolded()
                    topicElement.addSubTopic(intentTopic)
            except:
                pass
            informationGatheringTopic.getSubTopicByIndex(2).getSubTopicByIndex(1).addSubTopic(topicElement)
        if len(self.app.smaliChecks.getDynamicRegisteredBroadcastReceiversLocations()) > 0:
            dynamicRegisteredBroadcastReceiverTopic = TopicElement()
            dynamicRegisteredBroadcastReceiverTopic.setTitle("Dynamically Registered")
            self.createSubTopics(dynamicRegisteredBroadcastReceiverTopic,self.app.smaliChecks.getDynamicRegisteredBroadcastReceiversLocations())
            informationGatheringTopic.getSubTopicByIndex(2).getSubTopicByIndex(1).addSubTopic(dynamicRegisteredBroadcastReceiverTopic)
            if len(self.app.smaliChecks.getDynamicRegisteredBroadcastReceiversLocations()) > self.configuration.getXmindTopipFoldAt():
                dynamicRegisteredBroadcastReceiverTopic.setFolded()

        if len(self.app.getExportedReceivers()) > self.configuration.getXmindTopipFoldAt():
            informationGatheringTopic.getSubTopicByIndex(2).getSubTopicByIndex(1).setFolded()
        for provider in self.app.getExportedProviders():
            topicElement = TopicElement()
            topicElement.setTitle(provider)
            if self.app.getComponentPermission(provider) != "":
                permissionTopic = TopicElement()
                permissionTopic.setTitle("Permission: "+self.app.getComponentPermission(provider))
                topicElement.addSubTopic(permissionTopic)
            try:
                filters = self.app.getIntentFiltersList()[provider]
                i = 1
                for filter in filters:
                    intentTopic = TopicElement()
                    intentTopic.setTitle("Intent Filter " + str(i))
                    i += 1
                    action = TopicElement()
                    action.setTitle("Action")
                    self.createSubTopics(action, filter.getActionList())
                    category = TopicElement()
                    category.setTitle("Categories")
                    self.createSubTopics(category, filter.getCategoryList())
                    data = TopicElement()
                    data.setTitle("Data")
                    self.createSubTopics(data, filter.getDataList())
                    intentTopic.addSubTopic(action)
                    intentTopic.addSubTopic(category)
                    intentTopic.addSubTopic(data)
                    intentTopic.setFolded()
                    topicElement.addSubTopic(intentTopic)
            except:
                pass
            informationGatheringTopic.getSubTopicByIndex(2).getSubTopicByIndex(2).addSubTopic(topicElement)
        if len(self.app.getExportedProviders()) > self.configuration.getXmindTopipFoldAt():
            informationGatheringTopic.getSubTopicByIndex(2).getSubTopicByIndex(2).setFolded()
        for service in self.app.getExportedServices():
            topicElement = TopicElement()
            topicElement.setTitle(service)
            if self.app.getComponentPermission(service) != "":
                permissionTopic = TopicElement()
                permissionTopic.setTitle("Permission: "+self.app.getComponentPermission(service))
                topicElement.addSubTopic(permissionTopic)
            try:
                filters = self.app.getIntentFiltersList()[service]
                i = 1
                for filter in filters:
                    intentTopic = TopicElement()
                    intentTopic.setTitle("Intent Filter " + str(i))
                    i += 1
                    action = TopicElement()
                    action.setTitle("Action")
                    self.createSubTopics(action, filter.getActionList())
                    category = TopicElement()
                    category.setTitle("Categories")
                    self.createSubTopics(category, filter.getCategoryList())
                    data = TopicElement()
                    data.setTitle("Data")
                    self.createSubTopics(data, filter.getDataList())
                    intentTopic.addSubTopic(action)
                    intentTopic.addSubTopic(category)
                    intentTopic.addSubTopic(data)
                    intentTopic.setFolded()
                    topicElement.addSubTopic(intentTopic)
            except:
                pass
            informationGatheringTopic.getSubTopicByIndex(2).getSubTopicByIndex(3).addSubTopic(topicElement)
        if len(self.app.getExportedServices()) > self.configuration.getXmindTopipFoldAt():
            informationGatheringTopic.getSubTopicByIndex(2).getSubTopicByIndex(3).setFolded()

        # Files Topic

        topicElement = TopicElement()
        topicElement.setTitle("Files")
        topicElement.setPlainNotes("Excluded files/locations: "+self.configuration.getFileExclusions())
        fileTypes = ["Assets" ,"Libs" ,"Raw Resources" ,"Dex Classes" ,"Cordova Files","Xamarin Assemblies","Other"]
        tooManySubtopicsElement = TopicElement()
        tooManySubtopicsElement.setTitle("Too many files. Hit configured threshold.")
        self.createSubTopics(topicElement ,fileTypes)
        self.createSubTopics(topicElement.getSubTopicByIndex(0) ,self.app.getAssets())
        if len(self.app.getAssets()) > self.configuration.getXmindTopipFoldAt():
            topicElement.getSubTopicByIndex(0).setFolded()
        if len(self.app.getLibs()) > self.configuration.getXmindTopipFoldAt():
            topicElement.getSubTopicByIndex(1).setFolded()
        if len(self.app.getRawResources()) > self.configuration.getXmindTopipFoldAt():
            topicElement.getSubTopicByIndex(2).setFolded()
        if len(self.app.getCordovaFiles()) > self.configuration.getXmindTopipFoldAt():
            topicElement.getSubTopicByIndex(4).setFolded()
        if len(self.app.getXamarinAssemblies()) > self.configuration.getXmindTopipFoldAt():
            topicElement.getSubTopicByIndex(5).setFolded()
        if len(self.app.getOtherFiles()) > self.configuration.getXmindTopipFoldAt():
            topicElement.getSubTopicByIndex(6).setFolded()
        self.createSubTopics(topicElement.getSubTopicByIndex(1) ,self.app.getLibs())
        self.createSubTopics(topicElement.getSubTopicByIndex(2) ,self.app.getRawResources())
        self.createSubTopics(topicElement.getSubTopicByIndex(3), self.app.getDexFiles())
        self.createSubTopics(topicElement.getSubTopicByIndex(4), self.app.getCordovaFiles())
        self.createSubTopics(topicElement.getSubTopicByIndex(5), self.app.getXamarinAssemblies())
        if len(self.app.getOtherFiles()) <= self.app.configuration.getMaxSubTopics():
            self.createSubTopics(topicElement.getSubTopicByIndex(6), self.app.getOtherFiles())
        else:
            topicElement.getSubTopicByIndex(6).addSubTopic(tooManySubtopicsElement)
        informationGatheringTopic.addSubTopic(topicElement)

        # Object Usage Topic

        topicElement = TopicElement()
        topicElement.setTitle("Object Usage")
        objectsSubTopics = ["WebViews loadUrl","Cryptographic Functions", "Custom"]
        self.createSubTopics(topicElement, objectsSubTopics)

        if len(self.app.smaliChecks.getWebViewsLoadUrlUsageLocations()) > self.configuration.getXmindTopipFoldAt():
            topicElement.getSubTopicByIndex(0).setFolded()


        self.createSubTopics(topicElement.getSubTopicByIndex(0),self.app.smaliChecks.getWebViewsLoadUrlUsageLocations())
        encryptionSubTopic = TopicElement()
        encryptionSubTopic.setTitle("Encryption")
        self.createSubTopics(encryptionSubTopic, self.app.smaliChecks.getEncryptionFunctionsLocations())
        if (len(self.app.smaliChecks.getEncryptionFunctionsLocations()) > self.configuration.getXmindTopipFoldAt()):
            encryptionSubTopic.setFolded()

        decryptionSubtopic = TopicElement()
        decryptionSubtopic.setTitle("Decryption")
        self.createSubTopics(decryptionSubtopic, self.app.smaliChecks.getDecryptionFunctionsLocations())
        if (len(self.app.smaliChecks.getDecryptionFunctionsLocations()) > self.configuration.getXmindTopipFoldAt()):
            decryptionSubtopic.setFolded()

        undeterminedSubtopic = TopicElement()
        undeterminedSubtopic.setTitle("Undetermined")
        self.createSubTopics(undeterminedSubtopic, self.app.smaliChecks.getUndeterminedCryptographicFunctionsLocations())
        if (len(self.app.smaliChecks.getUndeterminedCryptographicFunctionsLocations()) > self.configuration.getXmindTopipFoldAt()):
            undeterminedSubtopic.setFolded()


        topicElement.getSubTopicByIndex(1).addSubTopic(encryptionSubTopic)
        topicElement.getSubTopicByIndex(1).addSubTopic(decryptionSubtopic)
        topicElement.getSubTopicByIndex(1).addSubTopic(undeterminedSubtopic)
        informationGatheringTopic.addSubTopic(topicElement)


        if len(self.app.smaliChecks.getCustomChecksLocations()) > 0:
            for check in self.app.smaliChecks.getCustomChecksLocations():
                customCheckSubTopic = TopicElement()
                customCheckSubTopic.setTitle(check)
                self.createSubTopics(customCheckSubTopic,self.app.smaliChecks.getCustomChecksLocations()[check])
                topicElement.getSubTopicByIndex(2).addSubTopic(customCheckSubTopic)
            if len(self.app.smaliChecks.getCustomChecksLocations()[check]) > self.configuration.getXmindTopipFoldAt():
                customCheckSubTopic.setFolded()


        # Improper Platform Usage


        topicElement = TopicElement()
        topicElement.setTitle("Improper Platform Usage")
        ipSubTopics = ["Malicious interaction possible with exported components?"]
        self.createSubTopics(topicElement ,ipSubTopics)
        topicElement.getSubTopicByIndex(0).setURLHyperlink \
            ("https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05h-Testing-Platform-Interaction.md#testing-for-sensitive-functionality-exposure-through-ipc")

        if(len(self.app.smaliChecks.getVulnerableContentProvidersSQLiLocations()) > 0):
            contentProviderSQLi = TopicElement()
            contentProviderSQLi.addMarker('flag-yellow')
            contentProviderSQLi.setTitle("Possibility of SQL Injection in exported ContentProvider")
            self.createSubTopics(contentProviderSQLi,self.app.smaliChecks.getVulnerableContentProvidersSQLiLocations())
            topicElement.addSubTopic(contentProviderSQLi)

        if (len(self.app.smaliChecks.getVulnerableContentProvidersPathTraversalLocations()) > 0):
            contentProviderPathTraversal = TopicElement()
            contentProviderPathTraversal.addMarker('flag-yellow')
            contentProviderPathTraversal.setTitle("Possibility of Path Traversal in exported ContentProvider")
            self.createSubTopics(contentProviderPathTraversal, self.app.smaliChecks.getVulnerableContentProvidersPathTraversalLocations())
            topicElement.addSubTopic(contentProviderPathTraversal)



        debuggableEvidenceTopic = TopicElement()
        debuggableEvidenceTopic.setURLHyperlink("https://github.com/OWASP/owasp-mstg/blob/master//Document/0x05i-Testing-Code-Quality-and-Build-Settings.md#testing-if-the-app-is-debuggable")
        if self.app.isDebuggable() == "Yes":
            debuggableEvidenceTopic.setTitle("Application is debuggable")
            debuggableEvidenceTopic.addMarker('flag-red')
            debuggableEvidenceTopic.setURLHyperlink(
                "https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05i-Testing-Code-Quality-and-Build-Settings.md#testing-if-the-app-is-debuggable")
        else:
            debuggableEvidenceTopic.setTitle("Application is not debuggable")
            debuggableEvidenceTopic.addMarker('flag-green')
        topicElement.addSubTopic(debuggableEvidenceTopic)

        activitiesVulnerableToPreferences = TopicElement()
        activitiesVulnerableToPreferences.setURLHyperlink("https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05h-Testing-Platform-Interaction.md#testing-for-fragment-injection")
        if len(self.app.getActivitiesExtendPreferencesWithoutValidate()) != 0 and int(self.app.getMinSDKVersion()) < 19:
            activitiesVulnerableToPreferences.setTitle("Activities vulnerable to Fragment Injection")
            self.createSubTopics(activitiesVulnerableToPreferences,self.app.getActivitiesExtendPreferencesWithoutValidate())
            activitiesVulnerableToPreferences.addMarker('flag-red')
        if len(self.app.getActivitiesExtendPreferencesWithValidate()) != 0:
            activitiesVulnerableToPreferences.setTitle("Activities with possible Fragment Injection (isValidFragment in place)")
            self.createSubTopics(activitiesVulnerableToPreferences, self.app.getActivitiesExtendPreferencesWithValidate())
            activitiesVulnerableToPreferences.addMarker('flag-yellow')
        if len(self.app.getActivitiesExtendPreferencesWithoutValidate()) == 0 and len(self.app.getActivitiesExtendPreferencesWithValidate()) == 0:
            activitiesVulnerableToPreferences.setTitle("No activities vulnerable to Fragment Injection")
            activitiesVulnerableToPreferences.addMarker('flag-green')
        topicElement.addSubTopic(activitiesVulnerableToPreferences)
        addJavascriptInterfaceTopic = TopicElement()
        if len(self.app.smaliChecks.getWebviewAddJavascriptInterfaceLocations()) != 0:
            if int(self.app.getMinSDKVersion()) <= 16:
                addJavascriptInterfaceTopic.setTitle("JavascriptInterface with RCE possibility")
                addJavascriptInterfaceTopic.addMarker('flag-red')
            else:
                addJavascriptInterfaceTopic.setTitle("JavascriptInterface available.")
                addJavascriptInterfaceTopic.addMarker('flag-yellow')
            self.createSubTopics(addJavascriptInterfaceTopic,self.app.smaliChecks.getWebviewAddJavascriptInterfaceLocations())
            if len(self.app.smaliChecks.getWebviewAddJavascriptInterfaceLocations()) > self.configuration.getXmindTopipFoldAt():
                addJavascriptInterfaceTopic.setFolded()
        else:
            addJavascriptInterfaceTopic.setTitle("No presence of JavascriptInterface")
            addJavascriptInterfaceTopic.addMarker('flag-green')
        addJavascriptInterfaceTopic.setURLHyperlink(
            "https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05h-Testing-Platform-Interaction.md#determining-whether-java-objects-are-exposed-through-webviews")
        topicElement.addSubTopic(addJavascriptInterfaceTopic)

        javascriptEnabledWebviewTopic = TopicElement()
        javascriptEnabledWebviewTopic.setURLHyperlink("https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05h-Testing-Platform-Interaction.md#determining-whether-java-objects-are-exposed-through-webviews")
        if len(self.app.smaliChecks.getJavascriptEnabledWebViews()) > 0:
            javascriptEnabledWebviewTopic.setTitle("WebView with Javascript enabled.")
            self.createSubTopics(javascriptEnabledWebviewTopic,self.app.smaliChecks.getJavascriptEnabledWebViews())
            javascriptEnabledWebviewTopic.addMarker('flag-yellow')
            if len(self.app.smaliChecks.getJavascriptEnabledWebViews()) > self.configuration.getXmindTopipFoldAt():
                javascriptEnabledWebviewTopic.setFolded()
        else:
            javascriptEnabledWebviewTopic.setTitle("No WebView with Javascript enabled.")
            javascriptEnabledWebviewTopic.addMarker('flag-green')
        topicElement.addSubTopic(javascriptEnabledWebviewTopic)
        fileAccessEnabledWebviewTopic = TopicElement()
        fileAccessEnabledWebviewTopic.setURLHyperlink("https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05h-Testing-Platform-Interaction.md#testing-webview-protocol-handlers")
        if len(self.app.smaliChecks.getFileAccessEnabledWebViews()) > 0:
            fileAccessEnabledWebviewTopic.setTitle("WebView with fileAccess enabled.")
            self.createSubTopics(fileAccessEnabledWebviewTopic, self.app.smaliChecks.getFileAccessEnabledWebViews())
            if int(self.app.getMinSDKVersion()) < 16:
                fileAccessEnabledWebviewTopic.setPlainNotes("This app runs in versions bellow API 16 (Jelly Bean). If webview is opening local HTML files via file URL and loading external resources it might be possible to bypass Same Origin Policy and extract local files since AllowUniversalAccessFromFileURLs is enabled by default and there is not public API to disable it in this versions.")
                fileAccessEnabledWebviewTopic.addMarker('flag-yellow')
            else:
                fileAccessEnabledWebviewTopic.addMarker('flag-yellow')
            if len(self.app.smaliChecks.getFileAccessEnabledWebViews()) > self.configuration.getXmindTopipFoldAt():
                fileAccessEnabledWebviewTopic.setFolded()
        else:
            fileAccessEnabledWebviewTopic.setTitle("No WebView with fileAccess enabled.")
            fileAccessEnabledWebviewTopic.addMarker('flag-green')
        topicElement.addSubTopic(fileAccessEnabledWebviewTopic)

        universalAccessEnabledWebviewTopic = TopicElement()
        if len(self.app.smaliChecks.getUniversalAccessFromFileURLEnabledWebviewsLocations()) > 0:
            self.createSubTopics(universalAccessEnabledWebviewTopic,self.app.smaliChecks.getUniversalAccessFromFileURLEnabledWebviewsLocations())
            universalAccessEnabledWebviewTopic.setTitle("WebView with Universal Access from File URLs enabled.")
            universalAccessEnabledWebviewTopic.addMarker('flag-yellow')
        else:
            universalAccessEnabledWebviewTopic.setTitle("No WebView with Universal Access from File URLs found.")
            universalAccessEnabledWebviewTopic.addMarker('flag-green')
        topicElement.addSubTopic(universalAccessEnabledWebviewTopic)

        methodologyTopic.addSubTopic(topicElement)



        # Insecure Communication Topic

        topicElement = TopicElement()
        topicElement.setTitle("Insecure Communication")
        icSubTopics = ["SSL Implementation" ,"Mixed Mode Communication?"]
        self.createSubTopics(topicElement ,icSubTopics)
        sslSubTopics = ["Accepts self-sign certificates?" ,"Accepts wrong host name?" ,"Lack of Certificate Pinning?"]
        self.createSubTopics(topicElement.getSubTopicByIndex(0) ,sslSubTopics)

        trustManagerSubTopic = TopicElement()
        trustManagerSubTopic.setURLHyperlink("https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05g-Testing-Network-Communication.md#verifying-the-server-certificate")
        if len(self.app.smaliChecks.getVulnerableTrustManagers()) != 0:
            trustManagerSubTopic.setTitle("Vulnerable Trust Manager:")
            self.createSubTopics(trustManagerSubTopic,self.app.smaliChecks.getVulnerableTrustManagers())
            topicElement.getSubTopicByIndex(0).addSubTopic(trustManagerSubTopic)
            trustManagerSubTopic.addMarker('flag-red')
        else:
            trustManagerSubTopic.setTitle("No vulnerable Trust Manager found.")
            trustManagerSubTopic.addMarker('flag-green')
        topicElement.getSubTopicByIndex(0).addSubTopic(trustManagerSubTopic)

        sslErrorBypassSubTopic = TopicElement()
        sslErrorBypassSubTopic.setURLHyperlink(
            "https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05g-Testing-Network-Communication.md#webview-server-certificate-verification")
        if len(self.app.smaliChecks.getVulnerableWebViewSSLErrorBypass()) != 0:
            sslErrorBypassSubTopic.setTitle("Webview with vulnerable SSL Implementation:")
            sslErrorBypassSubTopic.addMarker('flag-red')
            self.createSubTopics(sslErrorBypassSubTopic,self.app.smaliChecks.getVulnerableWebViewSSLErrorBypass())
        else:
            sslErrorBypassSubTopic.setTitle("No WebView with SSL Errror Bypass found.")
            sslErrorBypassSubTopic.addMarker('flag-green')
        topicElement.getSubTopicByIndex(0).addSubTopic(sslErrorBypassSubTopic)

        vulnerableHostnameVerifiersSubTopic = TopicElement()
        vulnerableHostnameVerifiersSubTopic.setURLHyperlink(
            "https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05g-Testing-Network-Communication.md#hostname-verification")
        if len(self.app.smaliChecks.getVulnerableHostnameVerifiers()) != 0:
            vulnerableHostnameVerifiersSubTopic.setTitle("Vulnerable HostnameVerifier found")
            vulnerableHostnameVerifiersSubTopic.addMarker('flag-red')
            self.createSubTopics(vulnerableHostnameVerifiersSubTopic,self.app.smaliChecks.getVulnerableHostnameVerifiers())
        else:
            vulnerableHostnameVerifiersSubTopic.setTitle("No vulnerable HostnameVerifiers found.")
            vulnerableHostnameVerifiersSubTopic.addMarker('flag-green')
        topicElement.getSubTopicByIndex(0).addSubTopic(vulnerableHostnameVerifiersSubTopic)

        vulnerableSetHostnameVerifiersSubTopic = TopicElement()
        vulnerableSetHostnameVerifiersSubTopic.setURLHyperlink(
            "hhttps://github.com/OWASP/owasp-mstg/blob/master/Document/0x05g-Testing-Network-Communication.md#hostname-verification")
        if len(self.app.smaliChecks.getVulnerableSetHostnameVerifier()) != 0:
            vulnerableSetHostnameVerifiersSubTopic.setTitle("setHostnameVerifier call with ALLOW_ALL_HOSTNAMES_VERIFIER")
            vulnerableSetHostnameVerifiersSubTopic.addMarker('flag-red')
            self.createSubTopics(vulnerableSetHostnameVerifiersSubTopic,self.app.smaliChecks.getVulnerableSetHostnameVerifier())
        else:
            vulnerableSetHostnameVerifiersSubTopic.setTitle("No vulnerable setHostnameVerifiers found.")
            vulnerableSetHostnameVerifiersSubTopic.addMarker('flag-green')
        topicElement.getSubTopicByIndex(0).addSubTopic(vulnerableSetHostnameVerifiersSubTopic)

        vulnerableSocketsSubTopic = TopicElement()
        vulnerableSocketsSubTopic.setURLHyperlink(
            "")
        if len(self.app.smaliChecks.getVulnerableSockets()) != 0:
            vulnerableSocketsSubTopic.setTitle(
                "Direct usage of Socket without HostnameVerifier")
            vulnerableSocketsSubTopic.addMarker('flag-red')
            self.createSubTopics(vulnerableSocketsSubTopic,
                                 self.app.smaliChecks.getVulnerableSockets())
        else:
            vulnerableSocketsSubTopic.setTitle("No direct usage of Socket without HostnameVerifiers.")
            vulnerableSocketsSubTopic.addMarker('flag-green')
        topicElement.getSubTopicByIndex(0).addSubTopic(vulnerableSocketsSubTopic)

        networkSecurityConfig = TopicElement()
        networkSecurityConfig.setURLHyperlink("https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05g-Testing-Network-Communication.md#network-security-configuration")
        if self.app.targetSDKVersion >= 25:
            if self.app.hasNetworkSecurityConfig == True:
                networkSecurityConfig.setTitle(
                    "Usage of NetworkSecurityConfig file.")
                domains = self.app.getNetworkSecurityConfigDomains()
                for domain in domains:
                    domainTopic = TopicElement()
                    domainTopic.setTitle(','.join(domain['domains']))

                    clearTextAllowedTopic = TopicElement()
                    clearTextAllowedTopic.setTitle("Clear Text Allowed")
                    clearTextAllowedValueTopic = TopicElement()
                    if str(domain['allowClearText']) == "True":
                        clearTextAllowedValueTopic.setTitle("Yes")
                        clearTextAllowedValueTopic.addMarker('flag-red')
                    else:
                        clearTextAllowedValueTopic.setTitle("No")
                        clearTextAllowedValueTopic.addMarker('flag-green')
                    clearTextAllowedTopic.addSubTopic(clearTextAllowedValueTopic)

                    allowUserCATopic = TopicElement()
                    allowUserCATopic.setTitle("User CA Trusted")
                    allowUserCAValueTopic = TopicElement()
                    if str(domain['allowUserCA']) == "True":
                        allowUserCAValueTopic.setTitle("Yes")
                        allowUserCAValueTopic.addMarker('flag-red')
                    else:
                        allowUserCAValueTopic.setTitle("No")
                        allowUserCAValueTopic.addMarker('flag-green')
                    allowUserCATopic.addSubTopic(allowUserCAValueTopic)

                    pinningTopic = TopicElement()
                    pinningTopic.setTitle("Pinning Configured")
                    pinningValueTopic = TopicElement()
                    if str(domain['pinning']) == "True":
                        pinningValueTopic.setTitle("Yes")
                        pinningValueTopic.addMarker('flag-green')
                        pinningExpirationTopic = TopicElement()
                        pinningExpirationValueTopic = TopicElement()
                        pinningExpirationTopic.setTitle("Pinning Expiration")
                        if domain['pinningExpiration'] != '':
                            date_format = "%Y-%m-%d"
                            a = datetime.strptime(domain['pinningExpiration'], date_format)
                            b = datetime.strptime(time.strftime("%Y-%m-%d"), date_format)
                            days =  (a-b).days
                            pinningExpirationValueTopic.setTitle(domain['pinningExpiration'])
                            if days <=0:
                                pinningExpirationValueTopic.addMarker('flag-red')
                                pinningExpirationValueTopic.setPlainNotes('Certificate Pinning is disabled. The expiration date on the pin-set has been reached.')
                            elif days < 60:
                                pinningExpirationValueTopic.addMarker('flag-yellow')
                                pinningExpirationValueTopic.setPlainNotes(str+(days)+' days for Certificate Pinning to be disabled.')
                        else:
                            pinningExpirationValueTopic.setTitle("No expiration")
                        pinningExpirationTopic.addSubTopic(pinningExpirationValueTopic)
                        pinningTopic.addSubTopic(pinningExpirationTopic)
                    else:
                        pinningValueTopic.setTitle("No")
                        pinningValueTopic.addMarker('flag-yellow')
                    pinningTopic.addSubTopic(pinningValueTopic)

                    domainTopic.addSubTopic(clearTextAllowedTopic)
                    domainTopic.addSubTopic(allowUserCATopic)
                    domainTopic.addSubTopic(pinningTopic)
                    networkSecurityConfig.addSubTopic(domainTopic)

            else:
                networkSecurityConfig.setTitle("No usage of NetworkSecurityConfig file.")
                networkSecurityConfig.addMarker('flag-yellow')
        else:
            networkSecurityConfig.setTitle(
                "NetworkSecurityConfig check ignored.")
            networkSecurityConfig.addMarker('flag-green')
            networkSecurityConfig.setPlainNotes("App is not targeting Android versions >= Nougat 7.0")
        topicElement.getSubTopicByIndex(0).addSubTopic(networkSecurityConfig)

        certificatePinningTopic = TopicElement()
        certificatePinningTopic.setURLHyperlink("https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05g-Testing-Network-Communication.md#testing-custom-certificate-stores-and-certificate-pinning")
        if len(self.app.smaliChecks.getOkHTTPCertificatePinningLocations())>0 or len(self.app.smaliChecks.getCustomCertificatePinningLocations())>0:
            certificatePinningTopic.setTitle("Possible Certificate Pinning Usage")
            certificatePinningTopic.addMarker('flag-green')
            okHttpCertificatePinningTopic = TopicElement()
            if len(self.app.smaliChecks.getOkHTTPCertificatePinningLocations())>0:
                okHttpCertificatePinningTopic.setTitle("OkHTTP Certificate Pinning.")
                self.createSubTopics(okHttpCertificatePinningTopic,self.app.smaliChecks.getOkHTTPCertificatePinningLocations())
                certificatePinningTopic.addSubTopic(okHttpCertificatePinningTopic)
            customCertificatePinningTopic = TopicElement()
            if len(self.app.smaliChecks.getCustomCertificatePinningLocations()) > 0:
                customCertificatePinningTopic.setTitle("Custom Certificate Pinning")
                self.createSubTopics(customCertificatePinningTopic,self.app.smaliChecks.getCustomCertificatePinningLocations())
                certificatePinningTopic.addSubTopic(customCertificatePinningTopic)
        else:
            certificatePinningTopic.setTitle("No usage of Certificate Pinning")
            certificatePinningTopic.addMarker('flag-yellow')
        topicElement.getSubTopicByIndex(0).addSubTopic(certificatePinningTopic)






        sslImplementationTopic = topicElement.getSubTopicByIndex(0)
        sslImplementationTopic.getSubTopicByIndex(0).setURLHyperlink \
            ("https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05g-Testing-Network-Communication.md#verifying-the-server-certificate")
        sslImplementationTopic.getSubTopicByIndex(1).setURLHyperlink \
            ("https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05g-Testing-Network-Communication.md#hostname-verification#hostname-verification")
        sslImplementationTopic.getSubTopicByIndex(2).setURLHyperlink \
            ("https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05g-Testing-Network-Communication.md#testing-custom-certificate-stores-and-certificate-pinning")
        methodologyTopic.addSubTopic(topicElement)


        # Insecure Data Storage Topic

        topicElement = TopicElement()
        topicElement.setTitle("Insecure Data Storage")
        idsSubTopics = ["Sensitive information stored in cleartext in sdcard/sandbox?"
                        ,"Sensitive information saved to system logs?"
                        ,"Background screenshot with sensitive information?"]
        self.createSubTopics(topicElement ,idsSubTopics)


        activitiesWithoutSecureFlagSubTopic = TopicElement()
        activitiesWithoutSecureFlagSubTopic.setURLHyperlink("https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05d-Testing-Data-Storage.md#finding-sensitive-information-in-auto-generated-screenshots")
        if len(self.app.getActivitiesWithoutSecureFlag()) != 0:
            activitiesWithoutSecureFlagSubTopic.setTitle("Activities without FLAG_SECURE or android:excludeFromRecents :")
            activitiesWithoutSecureFlagSubTopic.addMarker('flag-yellow')
            self.createSubTopics(activitiesWithoutSecureFlagSubTopic, self.app.getActivitiesWithoutSecureFlag())
            activitiesWithoutSecureFlagSubTopic.setFolded()
            if len(self.app.getActivitiesWithoutSecureFlag()) > self.configuration.getXmindTopipFoldAt():
                activitiesWithoutSecureFlagSubTopic.setFolded()
        else:
            activitiesWithoutSecureFlagSubTopic.setTitle("All activities have FLAG_SECURE or android:excludeFromRecents.")
            activitiesWithoutSecureFlagSubTopic.addMarker('flag-green')
        topicElement.addSubTopic(activitiesWithoutSecureFlagSubTopic)



        topicElement.getSubTopicByIndex(0).setURLHyperlink \
            ("https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05d-Testing-Data-Storage.md#testing-local-storage-for-sensitive-data")
        topicElement.getSubTopicByIndex(1).setURLHyperlink \
            ("https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05d-Testing-Data-Storage.md#testing-logs-for-sensitive-data")
        topicElement.getSubTopicByIndex(2).setURLHyperlink \
            ("https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05d-Testing-Data-Storage.md#finding-sensitive-information-in-auto-generated-screenshots")
        methodologyTopic.addSubTopic(topicElement)


        # Insufficient Cryptography Topic

        topicElement = TopicElement()
        topicElement.setTitle("Insufficient Cryptography")
        icrSubTopics = ["Using weak algorithms/modes?" ,"Using hardcoded properties?"]
        self.createSubTopics(topicElement ,icrSubTopics)
        topicElement.getSubTopicByIndex(0).setURLHyperlink \
            ("https://github.com/OWASP/owasp-mstg/blob/master/Document/0x04g-Testing-Cryptography.md#identifying-insecure-andor-deprecated-cryptographic-algorithms")
        topicElement.getSubTopicByIndex(1).setURLHyperlink \
            ("https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05e-Testing-Cryptography.md#verifying-the-configuration-of-cryptographic-standard-algorithms")
        AESTopic = TopicElement()
        AESTopic.setURLHyperlink("https://github.com/OWASP/owasp-mstg/blob/master/Document/0x04g-Testing-Cryptography.md#identifying-insecure-andor-deprecated-cryptographic-algorithms")
        if len(self.app.smaliChecks.getAESwithECBLocations()) > 0:
            AESTopic.setTitle("Usage of AES with ECB Mode")
            self.createSubTopics(AESTopic,self.app.smaliChecks.getAESwithECBLocations())
            AESTopic.addMarker('flag-red')
        else:
            AESTopic.setTitle("No usage of AES with ECB Mode")
            AESTopic.addMarker('flag-green')
        topicElement.addSubTopic(AESTopic)
        DESTopic = TopicElement()
        DESTopic.setURLHyperlink("https://github.com/OWASP/owasp-mstg/blob/master/Document/0x04g-Testing-Cryptography.md#identifying-insecure-andor-deprecated-cryptographic-algorithms")
        if len(self.app.smaliChecks.getDESLocations()) > 0:
            DESTopic.setTitle("Usage of DES or 3DES")
            self.createSubTopics(DESTopic,self.app.smaliChecks.getDESLocations())
            DESTopic.addMarker('flag-red')
        else:
            DESTopic.setTitle("No usage of DES or 3DES")
            DESTopic.addMarker('flag-green')
        topicElement.addSubTopic(DESTopic)

        keystoreTopic = TopicElement()
        if len(self.app.smaliChecks.getKeystoreLocations()) > 0:
            keystoreTopic.setTitle("Usage of Android KeyStore")
            keystoreTopic.addMarker('flag-green')
            self.createSubTopics(keystoreTopic,self.app.smaliChecks.getKeystoreLocations())
        else:
            keystoreTopic.setTitle("No usage of Android KeyStore")
            keystoreTopic.addMarker('flag-yellow')
        topicElement.addSubTopic(keystoreTopic)



        methodologyTopic.addSubTopic(topicElement)


        # Code Tampering Topic

        topicElement = TopicElement()
        topicElement.setTitle("Code Tampering")
        ctSubTopics = ["Lack of root detection?" ,"Lack of hooking detection?"]
        self.createSubTopics(topicElement ,ctSubTopics)
        topicElement.getSubTopicByIndex(0).setURLHyperlink \
            ("https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05j-Testing-Resiliency-Against-Reverse-Engineering.md#testing-root-detection")
        topicElement.getSubTopicByIndex(1).setURLHyperlink \
            ("https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05j-Testing-Resiliency-Against-Reverse-Engineering.md#testing-detection-of-reverse-engineering-tools")
        methodologyTopic.addSubTopic(topicElement)

        # Reverse Engineering Topic

        topicElement = TopicElement()
        topicElement.setTitle("Reverse Engineering")
        reSubTopics = ["Lack of code obfuscation?"]
        self.createSubTopics(topicElement ,reSubTopics)
        topicElement.getSubTopicByIndex(0).setURLHyperlink \
            ("https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05j-Testing-Resiliency-Against-Reverse-Engineering.md#testing-obfuscation")
        methodologyTopic.addSubTopic(topicElement)

        self.getRootTopic().addSubTopic(informationGatheringTopic)
        self.getRootTopic().addSubTopic(methodologyTopic)

    def createSubTopics(self ,topic ,subTopics):
        for subtopic in subTopics:
            newTopic = TopicElement()
            newTopic.setTitle(subtopic)
            topic.addSubTopic(newTopic)

    def save(self):
        cwd = os.path.dirname(os.path.realpath(__file__))
        filename = self.app.getPackageName( ) +".xmind"
        xmind.save(self.workbook ,cwd+"/output_xmind/"+filename)
        print "Generated output_xmind/" +filename
