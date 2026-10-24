import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P05_V2_ObsidianBeacon {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    private String obsidianBeaconData;

    private void sinkObsidianBeacon() throws XPathExpressionException {
        String data = obsidianBeaconData;
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

    public void runObsidianBeacon() throws XPathExpressionException {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = System.getenv("OBSIDIAN_BEACON_ADD");
        } else {
            data = null;
        }
        obsidianBeaconData = data;
        sinkObsidianBeacon();
    }
}
