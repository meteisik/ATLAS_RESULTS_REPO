import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P08_V1_ObsidianBeaconSafe {

    public void runObsidianBeacon() throws XPathExpressionException {
        String data;
        data = "foo";
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE643_P08_V1_ObsidianBeaconSafeSink()).sinkObsidianBeacon(dataArray);
    }
}

class CWE643_P08_V1_ObsidianBeaconSafeSink {

    public void sinkObsidianBeacon(String[] dataArray) throws XPathExpressionException {
        String data = dataArray[2];
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
