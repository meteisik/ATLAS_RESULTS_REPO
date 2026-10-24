import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P09_V1_RuneBeaconSafe {

    static class Container {
        public String containerOne;
    }

    public void runRuneBeacon() throws XPathExpressionException {
        String data;
        data = "foo";
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE643_P09_V1_RuneBeaconSafeSink()).sinkRuneBeacon(dataContainer);
    }
}

class CWE643_P09_V1_RuneBeaconSafeSink {

    public void sinkRuneBeacon(CWE643_P09_V1_RuneBeaconSafe.Container dataContainer) throws XPathExpressionException {
        String data = dataContainer.containerOne;
        String runeBeaconXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            runeBeaconXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            runeBeaconXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] runeBeaconTokens = data.split("||");
            if (runeBeaconTokens.length < 2) {
                return;
            }
            String runeBeaconUser = runeBeaconTokens[0];
            String runeBeaconPass = runeBeaconTokens[1];
            XPath runeBeaconXPath = XPathFactory.newInstance().newXPath();
            InputSource runeBeaconXml = new InputSource(runeBeaconXmlFile);
            String runeBeaconQuery = "//users/user[name/text()='" + runeBeaconUser
                    + "' and pass/text()='" + runeBeaconPass + "']" + "/secret/text()";
            String runeBeaconSecret = (String) runeBeaconXPath.evaluate(runeBeaconQuery, runeBeaconXml, XPathConstants.STRING);
            System.out.println(runeBeaconSecret);
        }
    }
}
