import re
from Configuration import *
from subprocess import *
from sys import platform


class NotFound(Exception):
    """Object not found in source code"""

class SmaliChecks:

    smaliPaths = []
    vulnerableTrustManagers=[]
    vulnerableWebViewSSLErrorBypass=[]
    vulnerableSetHostnameVerifiers = []
    vulnerableHostnameVerifiers = []
    vulnerableSocketsLocations = []
    dynamicRegisteredBroadcastReceiversLocations = []
    encryptionFunctionsLocation = []
    decryptionFunctionsLocation = []
    undeterminedCryptographicFunctionsLocation = []
    keystoreLocations = []
    webViewLoadUrlUsageLocation = []
    webViewAddJavascriptInterfaceUsageLocation = []
    okHttpCertificatePinningLocation = []
    customCertifificatePinningLocation = []
    AESwithECBLocations = []
    DESLocations =[]
    javascriptEnabledWebviews = []
    fileAccessEnabledWebviews = []
    universalAccessFromFileURLEnabledWebviewsLocations = []
    customChecksLocations = {}
    configuration = Configuration()

    def __init__(self, paths):
        for path in paths:
            self.smaliPaths.append(path)
        self.checkWebviewSSLErrorBypass()
        self.findWebviewJavascriptInterfaceUsage()
        self.findWeakCryptographicUsage()
        self.checkVulnerableTrustManagers()
        self.checkInsecureHostnameVerifier()
        self.checkVulnerableSockets()
        self.findEncryptionFunctions()
        self.checkVulnerableHostnameVerifiers()
        self.findWebViewLoadUrlUsage()
        self.findCustomChecks()
        self.findPropertyEnabledWebViews()
        self.checkOKHttpCertificatePinning()
        self.checkCustomPinningImplementation()
        self.findKeystoreUsage()
        self.findDynamicRegisteredBroadcastReceivers()
        self.findPathTraversalContentProvider()

    def getSmaliPaths(self):
        return self.smaliPaths

    def getOSGnuGrepCommand(self):
        if platform == "darwin":
            return "ggrep"
        else:
            return "grep"


    def checkForExistenceInFolder(self,objectRegEx,folderPath):
        command = [self.getOSGnuGrepCommand(),"-s" ,"-r", "-l", "-P",objectRegEx," --exclude-dir="+self.configuration.getFolderExclusions()]
        for path in folderPath:
            command.append(path)
        grep = Popen(command, stdout=PIPE)
        filePaths = grep.communicate()[0].strip().split('\n')
        if len(filePaths) > 0:
            return filePaths
        else:
            raise NotFound

    def existsInFile(self,objectRegEx,filePath):
        grep = Popen([self.getOSGnuGrepCommand(),"-l", "-P",objectRegEx,filePath], stdout=PIPE)
        filePaths = grep.communicate()[0].strip().split('\n')
        if len(filePaths) > 0:
            return filePaths
        else:
            return False

    def getMethodCompleteInstructions(self,methodRegEx,filePath):
        sed = Popen(["sed", "-n", methodRegEx, filePath], stdout=PIPE)
        methodContent = sed.communicate()[0]
        return methodContent.strip().replace('    ','').split('\n')

    def getFileContent(self,filePath):
        sed = Popen(["sed", "1p",filePath], stdout=PIPE)
        fileContent = sed.communicate()[0]
        return fileContent.strip().replace('    ', '').split('\n')

    def getMethodInstructions(self,methodRegEx,filePath):
        sed = Popen(["sed", "-n", methodRegEx, filePath], stdout=PIPE)
        methodContent = sed.communicate()[0]
        try:
            match = re.search(r".locals \d{1,}([\S\s]*?).end method", methodContent)
            instructions = str(match.group(1)).strip().replace('    ','').split('\n')
            return instructions
        except:
            return ""

    def isMethodEmpty(self,instructions):
        for i in range(len(instructions)-1,0,-1):
            if instructions[i] == '.end method':
                continue
            else:
                if instructions[i] == "return-void":
                    return True
                else:
                    return False

    def hasOperationProceed(self,instructions):
        for i in range(len(instructions) - 1, 0, -1):
            if 'Landroid/webkit/SslErrorHandler;->proceed()V' in instructions[i]:
                return True
            else:
                continue
        return False

    def doesMethodReturnNull(self,instructions):
        for i in range(len(instructions) - 1, 0, -1):
            if instructions[i] == "return-object v0":
                if i-2 >= 0  and instructions[i-2] == "const/4 v0, 0x0":
                    return True
                elif i-2 >=0 and instructions[i-2] == "new-array v0, v0, [Ljava/security/cert/X509Certificate;":
                    if i-4 >= 0 and instructions[i - 4] == "const/4 v0, 0x0":
                        return True
                    else:
                        return False
                else:
                    return False
            else:
                continue
        return False

    def doesMethodReturnTrue(self,instructions):
        maxLen = len(instructions)-1
        for i in range(maxLen, 0, -1):
            if instructions[i] == "return v0":
                if i-2 >= 0 and instructions[i-2] == "const/4 v0, 0x1":
                    return True
                else:
                    return False
            else:
                continue
        return False


    #Returns the register that has the target value assigned

    def searchRegisterByAssignedValue(self,instructions,value):
        register = ""
        for instruction in instructions:
            if "const/" in instruction and value in instruction:
                registerEnd = instruction.find(",")
                registerBegin = instruction.find(" ",0,registerEnd)+1
                register = instruction[registerBegin:registerEnd]
                break
        return register


    #Returns the assigned value to the targer register.

    def getAssignedValueByRegister(self,instructions,register):
        register = ""
        for instruction in instructions:
            if "const/" in instruction and register in instruction:
                registerEnd = instruction.find(",")
                registerBegin = instruction.find(" ",0,registerEnd)+1
                register = instruction[registerBegin:registerEnd]
                break
        return register


    def doesActivityExtendsPreferenceActivity(self,activity):
        activity = activity.replace(".","/")
        activityLocation = self.checkForExistenceInFolder(".class public([a-zA-Z\s]*)L"+activity+";",self.getSmaliPaths())
        if activityLocation[0] != "":
            preferenceExtends = self.existsInFile(".super Landroid\/preference\/PreferenceActivity;",activityLocation[0])
            if preferenceExtends[0] != '':
                return True
            else:
                return False

    def doesPreferenceActivityHasValidFragmentCheck(self,activity):
        activity = activity.replace(".","/")
        activityLocation = self.checkForExistenceInFolder(".class public([a-zA-Z\s]*)L"+activity+";",self.getSmaliPaths())
        if activityLocation[0] != "":
            isValidFragmentFunction = self.getMethodCompleteInstructions('/.method protected isValidFragment(Ljava\/lang\/String;)Z/,/^.end method/p',activityLocation[0])
            if isValidFragmentFunction[0] != '':
                return True
            else:
                return False

    def doesActivityHasFlagSecure(self,activity):
        activity = activity.replace(".","/")
	end = activity.rfind('/')+1
	customPath = []
        x = len(self.getSmaliPaths())
	for a in range(0,x):
		customPath.append(self.getSmaliPaths()[a]+activity[:end])
        activityLocation = self.checkForExistenceInFolder(".class public([a-zA-Z\s]*)L"+activity+";",customPath)
        if activityLocation[0] != "":
            methodInstructions = self.getMethodCompleteInstructions('/.method \([a-zA-Z]* \)onCreate(Landroid\/os\/Bundle;)V/,/^.end method/p',activityLocation[0])
            register = self.searchRegisterByAssignedValue(methodInstructions,"0x2000")
            if register.strip() == "":
		        return False
            else:
                flag = self.existsInFile("invoke-virtual.*"+register+".*Landroid\/view\/Window;->setFlags\(II\)V",activityLocation[0])
                if flag[0] != '':
                    return True
                else:
                    return False

    def findRegisterAssignedValueFromIndexBackwards(self,instructionsList,register,index):
        for pointer in range(index,0,-1):
            if register in instructionsList[pointer] and ("const" in instructionsList[pointer] or "sget-object" in instructionsList[pointer]):
                valueBegin = instructionsList[pointer].find(",")
                value = instructionsList[pointer][valueBegin+2:]
                return value

    def findRegistersPassedToFunction(self,functionInstruction):
        match = re.search(r"{(.*)}", functionInstruction)
        try:
            if "range" in functionInstruction:
                registers = str(match.group(1)).strip().replace(' ', '').split("..")
            else:
                registers = str(match.group(1)).strip().replace(' ','').split(",")
        except:
            match = re.search(r"\D\d", functionInstruction)
            try:
                registers = str(match.group(0))
            except:
                return ""
        return registers

    def findInstructionIndex(self,instructionsList,instructionToSearch):
        indexList = []
        for index,instruction in enumerate(instructionsList):
            m = re.search(instructionToSearch,instruction)
            try:
                output = m.group(0)
                indexList.append(index)
            except:
                continue
        return indexList



    def findDynamicRegisteredBroadcastReceivers(self):
        dynamicRegisteredBroadcastReceiversLocations = self.checkForExistenceInFolder(
            ";->registerReceiver\(Landroid\/content\/BroadcastReceiver;Landroid\/content\/IntentFilter;\)",
            self.getSmaliPaths())
        for location in dynamicRegisteredBroadcastReceiversLocations:
            self.dynamicRegisteredBroadcastReceiversLocations.append(location)


    def findEncryptionFunctions(self):
        encryptionFunctionsLocations = self.checkForExistenceInFolder("invoke-virtual {(.*)}, Ljavax\/crypto\/Cipher;->init\(ILjava\/security\/Key",self.getSmaliPaths())
        if encryptionFunctionsLocations[0] != "":
            for location in encryptionFunctionsLocations:
                if "org/bouncycastle" in location:
                    continue
                instructions = self.getFileContent(location)
                indexList = self.findInstructionIndex(instructions,"Ljavax/crypto/Cipher;->init\(ILjava/security/Key")
                if len(indexList) != 0:
                    for index in indexList:
                        registers = self.findRegistersPassedToFunction(instructions[index])
                        if self.findRegisterAssignedValueFromIndexBackwards(instructions,registers[1],index) == "0x1":
                            self.encryptionFunctionsLocation.append(location)
                        elif self.findRegisterAssignedValueFromIndexBackwards(instructions,registers[1],index) == "0x2":
                            self.decryptionFunctionsLocation.append(location)
                        else:
                            if location not in self.undeterminedCryptographicFunctionsLocation:
                                self.undeterminedCryptographicFunctionsLocation.append(location)

    def findKeystoreUsage(self):
        keystoreUsageLocations = self.checkForExistenceInFolder("invoke-virtual {(.*)}, Ljava\/security\/KeyStore;->getEntry\(Ljava\/lang\/String;Ljava\/security\/KeyStore\$ProtectionParameter;\)Ljava\/security\/KeyStore\$Entry",self.getSmaliPaths())
        if keystoreUsageLocations[0] != "":
            for location in keystoreUsageLocations:
                self.keystoreLocations.append(location)

    def findWebViewLoadUrlUsage(self):
        webViewUsageLocations = self.checkForExistenceInFolder("Landroid\/webkit\/WebView;->loadUrl\(Ljava\/lang\/String;\)V",self.getSmaliPaths())
        if webViewUsageLocations[0] != "":
            for location in webViewUsageLocations:
                self.webViewLoadUrlUsageLocation.append(location)


    # *** Improper Platform Usage ***

    def findPathTraversalContentProvider(self):
        contentProvidersLocations = self.checkForExistenceInFolder(".super Landroid\/content\/ContentProvider;",self.getSmaliPaths())
        if contentProvidersLocations[0] != '':
            for location in contentProvidersLocations:
                instructions = self.getFileContent(location)
                indexList = self.findInstructionIndex(instructions,".method public openFile\(Landroid\/net\/Uri;Ljava\/lang\/String;\)Landroid\/os\/ParcelFileDescriptor;")
                if len(indexList) > 0:
                    indexList = self.findInstructionIndex(instructions,"Ljava\/io\/File;->getCanonicalPath\(\)")


    def findWeakCryptographicUsage(self):
        getInstanceLocations = self.checkForExistenceInFolder("Ljavax\/crypto\/Cipher;->getInstance\(Ljava\/lang\/String;\)Ljavax\/crypto\/Cipher;",self.getSmaliPaths())
        if getInstanceLocations[0] != '':
            for location in getInstanceLocations:
                instructions = self.getFileContent(location)
                indexList = self.findInstructionIndex(instructions,"Ljavax/crypto/Cipher;->getInstance\(Ljava/lang/String;\)Ljavax/crypto/Cipher;")
                for index in indexList:
		    register = self.findRegistersPassedToFunction(instructions[index])
                    transformationValue = self.findRegisterAssignedValueFromIndexBackwards(instructions, register[0], index)
                    if transformationValue is not None:
                        if transformationValue == "\"AES\"" or "AES/ECB/" in transformationValue:
                            self.AESwithECBLocations.append(location)
                        elif "DES" in transformationValue:
                            self.DESLocations.append(location)


    def findPropertyEnabledWebViews(self):
        webviewUsageLocations = self.checkForExistenceInFolder(";->getSettings\(\)Landroid\/webkit\/WebSettings;",self.getSmaliPaths())
        if webviewUsageLocations[0] != '':
            for location in webviewUsageLocations:
                instructions = self.getFileContent(location)
                indexList = self.findInstructionIndex(instructions,"Landroid/webkit/WebSettings;->setJavaScriptEnabled\(Z\)V")
                if len(indexList) > 0:
                    for index in indexList:
                        register = self.findRegistersPassedToFunction(instructions[index])
                        value = self.findRegisterAssignedValueFromIndexBackwards(instructions,register[1],index)
                        if value == "0x1":
                            self.javascriptEnabledWebviews.append(location)
                indexList = self.findInstructionIndex(instructions,"Landroid/webkit/WebSettings;->setAllowFileAccess\(Z\)V")
                if len(indexList) > 0:
                    for index in indexList:
                        register = self.findRegistersPassedToFunction(instructions[index])
                        value = self.findRegisterAssignedValueFromIndexBackwards(instructions, register[1], index)
                        if value == "0x1":
                            self.fileAccessEnabledWebviews.append(location)
                else:
                    self.fileAccessEnabledWebviews.append(location)
                indexList = self.findInstructionIndex(instructions,"Landroid/webkit/WebSettings;->setAllowUniversalAccessFromFileURLs\(Z\)V")
                if len(indexList) > 0:
                    for index in indexList:
                        register = self.findRegistersPassedToFunction(instructions[index])
                        value = self.findRegisterAssignedValueFromIndexBackwards(instructions, register[1], index)
                        if value == "0x1":
                            self.universalAccessFromFileURLEnabledWebviewsLocations.append(location)



    def findWebviewJavascriptInterfaceUsage(self):
        javascriptInterfaceLocations = self.checkForExistenceInFolder(";->addJavascriptInterface\(Ljava\/lang\/Object;Ljava\/lang\/String;\)V",self.getSmaliPaths())
        if javascriptInterfaceLocations[0] != '':
            for location in javascriptInterfaceLocations:
                instructions = self.getFileContent(location)
                indexList = self.findInstructionIndex(instructions,";->addJavascriptInterface\(Ljava/lang/Object;Ljava/lang/String;\)V")
                if len(indexList) != 0:
                    for index in indexList:
                        registers = self.findRegistersPassedToFunction(instructions[index])
                    self.webViewAddJavascriptInterfaceUsageLocation.append(location)


    # *** Insecure Communication Checks ***

    #Check for the implementation of custom HostnameVerifiers

    def checkInsecureHostnameVerifier(self):
        insecureHostNameVerifierLocations = self.checkForExistenceInFolder(".implements Ljavax\/net\/ssl\/HostnameVerifier;",self.getSmaliPaths())
        if insecureHostNameVerifierLocations[0] != '':
            for location in insecureHostNameVerifierLocations:
                methodInstructions = self.getMethodCompleteInstructions('/.method .* verify(Ljava\/lang\/String;Ljavax\/net\/ssl\/SSLSession;)Z/,/^.end method/p',location)
                if methodInstructions != "":
                    if self.doesMethodReturnTrue(methodInstructions) == True:
                        self.vulnerableHostnameVerifiers.append(location)

    #Check for the presence of the custom function that allows to bypass SSL errors in WebViews

    def checkWebviewSSLErrorBypass(self):
        webviewErrorBypassLocations = self.checkForExistenceInFolder("Landroid\/webkit\/SslErrorHandler;->proceed\(\)V",self.getSmaliPaths())
        if webviewErrorBypassLocations[0] != '':
            for location in webviewErrorBypassLocations:
                self.vulnerableWebViewSSLErrorBypass.append(location)

    #Check for the presence of custom TrustManagers that are vulnerable.

    def checkVulnerableTrustManagers(self):
        vulnerableTrustManagers = []
        try:
            checkClientTrustedLocations = self.checkForExistenceInFolder(".method public checkClientTrusted\(\[Ljava\/security\/cert\/X509Certificate;Ljava\/lang\/String;\)V",self.getSmaliPaths())
            if checkClientTrustedLocations[0] != '':
                for location in checkClientTrustedLocations:
                    methodInstructions = self.getMethodCompleteInstructions('/method public checkClientTrusted\(\)/,/^.end method/p',location)
                    if methodInstructions != "":
                        if self.isMethodEmpty(methodInstructions) == True:
                            getAcceptedIssuersLocations = self.existsInFile(".method public getAcceptedIssuers\(\)\[Ljava\/security\/cert\/X509Certificate;",location)
                            if methodInstructions != "":
                                methodInstructions = self.getMethodCompleteInstructions('/method public getAcceptedIssuers()\[Ljava\/security\/cert\/X509Certificate;/,/^.end method/p',getAcceptedIssuersLocations[0])
                                if self.doesMethodReturnNull(methodInstructions) == True:
                                    checkServerTrustedLocations = self.existsInFile(".method public checkServerTrusted\(\[Ljava\/security\/cert\/X509Certificate;Ljava\/lang\/String;\)V",location)
                                    if methodInstructions != "":
                                        methodInstructions = self.getMethodCompleteInstructions('/method public checkServerTrusted\(\)/,/^.end method/p', checkServerTrustedLocations[0])
                                        if self.isMethodEmpty(methodInstructions) == True:
                                            vulnerableTrustManagers.append(location)
                                            self.vulnerableTrustManagers.append(location)
                return vulnerableTrustManagers
        except NotFound:
            pass

    #Check for the presence of setHostnameVerifier with ALLOW_ALL_HOSTNAME_VERIFIER

    def checkVulnerableHostnameVerifiers(self):
        setHostnameVerifierLocations = self.checkForExistenceInFolder("invoke-virtual {(.*)}, Lorg\/apache\/http\/conn\/ssl\/SSLSocketFactory;->setHostnameVerifier\(Lorg\/apache\/http\/conn\/ssl\/X509HostnameVerifier;\)V",self.getSmaliPaths())
        if setHostnameVerifierLocations[0] != "":
            for location in setHostnameVerifierLocations:
                instructions = self.getFileContent(location)
                indexList = self.findInstructionIndex(instructions,"Lorg/apache/http/conn/ssl/SSLSocketFactory;->setHostnameVerifier")
                if len(indexList) != 0:
                    for index in indexList:
                        registers = self.findRegistersPassedToFunction(instructions[index])
                        if self.findRegisterAssignedValueFromIndexBackwards(instructions, registers[1], index) == "Lorg/apache/http/conn/ssl/SSLSocketFactory;->ALLOW_ALL_HOSTNAME_VERIFIER:Lorg/apache/http/conn/ssl/X509HostnameVerifier;":
                            self.vulnerableSetHostnameVerifiers.append(location)

    #Check for SocketFactory without Hostname Verify

    def checkVulnerableSockets(self):
        vulnerableSocketsLocations = self.checkForExistenceInFolder("Ljavax\/net\/SocketFactory;->createSocket\(Ljava\/lang\/String;I\)Ljava\/net\/Socket;",self.getSmaliPaths())
        if vulnerableSocketsLocations[0] != "":
            for location in vulnerableSocketsLocations:
                instructions = self.getFileContent(location)
                indexList = self.findInstructionIndex(instructions,"Ljavax/net/ssl/HostnameVerifier;->verify\(Ljava/lang/String;Ljavax/net/ssl/SSLSession;\)Z")
                if len(indexList) == 0:
                    self.vulnerableSocketsLocations.append(location)

    #Check for the implementation of OKHttp Certificate Pinning

    def checkOKHttpCertificatePinning(self):
        okHttpCertificatePinningLocations = self.checkForExistenceInFolder("add\(Ljava\/lang\/String;\[Ljava\/lang\/String;\)Lokhttp3\/CertificatePinner\$Builder",self.getSmaliPaths())
        if okHttpCertificatePinningLocations[0] != '':
            for location in okHttpCertificatePinningLocations:
                #Bypass library files
                if "/okhttp" in location:
                    continue
                instructions = self.getFileContent(location)
                indexList = self.findInstructionIndex(instructions,"certificatePinner\(Lokhttp3/CertificatePinner;\)Lokhttp3/OkHttpClient$Builder;")
                if len(indexList) == 0:
                    self.okHttpCertificatePinningLocation.append(location)

    #Check for custom Certificate Pinning Implementation

    def checkCustomPinningImplementation(self):
        customCertificatePinningLocations = self.checkForExistenceInFolder("invoke-virtual {(.*)}, Ljavax\/net\/ssl\/TrustManagerFactory;->init\(Ljava\/security\/KeyStore;\)V",self.getSmaliPaths())
        if customCertificatePinningLocations[0] != '':
            for location in customCertificatePinningLocations:
                if "/okhttp" in location or "io/fabric" in location:
                    continue
                self.customCertifificatePinningLocation.append(location)


    # *** CUSTOM CHECKS ***


    def findCustomChecks(self):
        for check in self.configuration.getCustomChecks():
                self.customChecksLocations[check[0]] = []
                customCheckLocationsFound = self.checkForExistenceInFolder(check[1],self.getSmaliPaths())
                if customCheckLocationsFound[0] != '':
                    for location in customCheckLocationsFound:
                        self.customChecksLocations[check[0]].append(location)
    # *** GETTERS ***

    def getVulnerableTrustManagers(self):
        return self.vulnerableTrustManagers

    def getVulnerableWebViewSSLErrorBypass(self):
        return self.vulnerableWebViewSSLErrorBypass

    def getVulnerableHostnameVerifiers(self):
        return self.vulnerableHostnameVerifiers

    def getEncryptionFunctionsLocations(self):
        return self.encryptionFunctionsLocation

    def getDecryptionFunctionsLocations(self):
        return self.decryptionFunctionsLocation

    def getUndeterminedCryptographicFunctionsLocations(self):
        return self.undeterminedCryptographicFunctionsLocation

    def getVulnerableSetHostnameVerifier(self):
        return self.vulnerableSetHostnameVerifiers

    def getVulnerableSockets(self):
        return self.vulnerableSocketsLocations

    def getWebViewsLoadUrlUsageLocations(self):
        return self.webViewLoadUrlUsageLocation

    def getCustomChecksLocations(self):
        return self.customChecksLocations

    def getWebviewAddJavascriptInterfaceLocations(self):
        return self.webViewAddJavascriptInterfaceUsageLocation

    def getAESwithECBLocations(self):
        return self.AESwithECBLocations

    def getDESLocations(self):
        return self.DESLocations

    def getJavascriptEnabledWebViews(self):
        return self.javascriptEnabledWebviews

    def getFileAccessEnabledWebViews(self):
        return self.fileAccessEnabledWebviews

    def getUniversalAccessFromFileURLEnabledWebviewsLocations(self):
        return self.universalAccessFromFileURLEnabledWebviewsLocations

    def getOkHTTPCertificatePinningLocations(self):
        return self.okHttpCertificatePinningLocation

    def getCustomCertificatePinningLocations(self):
        return self.customCertifificatePinningLocation

    def getKeystoreLocations(self):
        return self.keystoreLocations

    def getDynamicRegisteredBroadcastReceiversLocations(self):
        return self.dynamicRegisteredBroadcastReceiversLocations
