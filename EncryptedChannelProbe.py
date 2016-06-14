__author__ = 'Filippo Gaudenzi'
__email__ = 'filippo.gaudenzi@unimi.it'

from testagent.probe import Probe
from libnmap.process import NmapProcess
from libnmap.parser import NmapParser, NmapParserException

#TODO controlli
class EncryptedChannelProbe(Probe):
    def nmapRun (self, inputs):
      def do_scan(targets,options):
        parsed = None
        proc = NmapProcess(targets,options)
        running = proc.run()
        if running != 0:
          raise Exception("Scan failed")
        resultnmap=proc.stdout
        return NmapParser.parse(resultnmap)
      options = ""
      options = options + " --script ssl-cert,ssl-enum-ciphers "
      options = options + " -Pn -p"+self.testinstances["config"]["port"]
      #if testInstances["2"]["ENABLE_TCP_SCAN"] == "1":
      #  options = options + "S" if testInstances["2"]["TCP_SYN_SCAN"] == "True" else options + "T"
      #if testInstances["2"]["ENABLE_UDP_SCAN"] == "1":
      #  options = options + "U"
      
      scanResults = do_scan(self.testinstances["config"]["host"],options)
      for host in scanResults.hosts:
        if host.get_service(int(self.testinstances["config"]["port"])).open():
          print "PORT "+self.testinstances["config"]["port"]+" OPEN"
          s=host.get_service(int(self.testinstances["config"]["port"]))
          result=s.scripts_results
        if not result:
          return False
        else:  
          issuer=result[0]['elements']['issuer']
          pubkey=result[0]['elements']['pubkey']
          validity=result[0]['elements']['validity']
          print "ISSUED by: "+"country:"+issuer['country']+" - Organization name:" issuer['organizationName']+" - Common name:"+issuer['commonName']
          print "Pub key:"+pubkey["bits"]+"/"+pubkey["type"]
          print "Validity till:"+validity["notAfter"]
          strength=result[1]['elements']['least strength']
          if(strength=='A'):
            return True
          if(strength=='B'):
            return True
          if(strength=='C'):
            return False
          if(strength=='D'):
            return False
          if(strength=='E'):
            return False
          if(strength=='F'):
            return False
          if(strength=='weak'):
            return False
          if(strength=='strong'):
            return True
    def nmapRunR (self, inputs):
      return
    def appendAtomics(self):
        self.appendAtomic(self.nmapRun, self.nmapRunR)
        #seld.appendAtomic(self.nmapParse,self.nmapParseR)

probe = EncryptedChannelProbe


