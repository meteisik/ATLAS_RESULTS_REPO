import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P07_V1_ObsidianBeacon {

    public void runObsidianBeacon() throws XPathExpressionException {
        String data;
        data = (new CWE643_P07_V1_ObsidianBeaconSource()).sourceObsidianBeacon();
        String obsidianBeaconXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            obsidianBeaconXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            obsidianBeaconXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] obsidianBeaconTokens = data.split("||");
            if (obsidianBeaconTokens.length < 2) {
                return;
            }
            String obsidianBeaconUser = obsidianBeaconTokens[0];
            String obsidianBeaconPass = obsidianBeaconTokens[1];
            XPath obsidianBeaconXPath = XPathFactory.newInstance().newXPath();
            InputSource obsidianBeaconXml = new InputSource(obsidianBeaconXmlFile);
            String obsidianBeaconQuery = "//users/user[name/text()='" + obsidianBeaconUser
                    + "' and pass/text()='" + obsidianBeaconPass + "']" + "/secret/text()";
            String obsidianBeaconSecret = (String) obsidianBeaconXPath.evaluate(obsidianBeaconQuery, obsidianBeaconXml, XPathConstants.STRING);
            System.out.println(obsidianBeaconSecret);
        }
    }
}

class CWE643_P07_V1_ObsidianBeaconSource {

    public String sourceObsidianBeacon() {
        String data;
        data = System.getenv("OBSIDIAN_BEACON_ADD");
        return data;
    }
}
