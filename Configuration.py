import ConfigParser
import os

class Configuration:

    file = "droidstatx.config"
    configParser = ConfigParser.ConfigParser()

    def __init__(self):
        cwd = os.path.dirname(os.path.realpath(__file__))
        self.configParser.read(cwd+"/"+self.file)

    def geXmindTopicStructure(self):
        return self.configParser.get("Settings", "xmindTopicStructure")

    def getXmindTopipFoldAt(self):
        return int(self.configParser.get("Settings", "topicFoldAt"))

    def getFileExclusions(self):
        return self.configParser.get("Settings", "fileExclusions")

    def getFolderExclusions(self):
        return self.configParser.get("Settings","folderExclusions")

    def getMaxSubTopics(self):
        return int(self.configParser.get("Settings","maxSubTopics"))

    def getCustomChecks(self):
        checksList = []
        for section in self.configParser.sections():
            if section == "CustomChecks":
                options = self.configParser.options(section)
                for option in options:
                    checksList.append([option,self.configParser.get(section, option)])
        return checksList

