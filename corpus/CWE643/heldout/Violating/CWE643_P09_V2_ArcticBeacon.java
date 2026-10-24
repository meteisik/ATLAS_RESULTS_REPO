import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P09_V2_ArcticBeacon {
    private static int privateFive = 5;

    static class Container {
        public String containerOne;
    }

    public void runArcticBeacon() throws XPathExpressionException {
        String data;
        if (privateFive == 5) {
            data = System.getenv("ARCTIC_BEACON_ADD");
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE643_P09_V2_ArcticBeaconSink()).sinkArcticBeacon(dataContainer);
    }
}

class CWE643_P09_V2_ArcticBeaconSink {

    public void sinkArcticBeacon(CWE643_P09_V2_ArcticBeacon.Container dataContainer) throws XPathExpressionException {
        String data = dataContainer.containerOne;
        String arcticBeaconXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            arcticBeaconXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            arcticBeaconXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] arcticBeaconTokens = data.split("||");
            if (arcticBeaconTokens.length < 2) {
                return;
            }
            String arcticBeaconUser = arcticBeaconTokens[0];
            String arcticBeaconPass = arcticBeaconTokens[1];
            XPath arcticBeaconXPath = XPathFactory.newInstance().newXPath();
            InputSource arcticBeaconXml = new InputSource(arcticBeaconXmlFile);
            String arcticBeaconQuery = "//users/user[name/text()='" + arcticBeaconUser
                    + "' and pass/text()='" + arcticBeaconPass + "']" + "/secret/text()";
            String arcticBeaconSecret = (String) arcticBeaconXPath.evaluate(arcticBeaconQuery, arcticBeaconXml, XPathConstants.STRING);
            System.out.println(arcticBeaconSecret);
        }
    }
}
