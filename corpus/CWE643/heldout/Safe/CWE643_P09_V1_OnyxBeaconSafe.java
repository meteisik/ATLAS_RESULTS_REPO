import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P09_V1_OnyxBeaconSafe {

    static class Container {
        public String containerOne;
    }

    public void runOnyxBeacon() throws XPathExpressionException {
        String data;
        data = "foo";
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE643_P09_V1_OnyxBeaconSafeSink()).sinkOnyxBeacon(dataContainer);
    }
}

class CWE643_P09_V1_OnyxBeaconSafeSink {

    public void sinkOnyxBeacon(CWE643_P09_V1_OnyxBeaconSafe.Container dataContainer) throws XPathExpressionException {
        String data = dataContainer.containerOne;
        String onyxBeaconXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            onyxBeaconXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            onyxBeaconXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] onyxBeaconTokens = data.split("||");
            if (onyxBeaconTokens.length < 2) {
                return;
            }
            String onyxBeaconUser = onyxBeaconTokens[0];
            String onyxBeaconPass = onyxBeaconTokens[1];
            XPath onyxBeaconXPath = XPathFactory.newInstance().newXPath();
            InputSource onyxBeaconXml = new InputSource(onyxBeaconXmlFile);
            String onyxBeaconQuery = "//users/user[name/text()='" + onyxBeaconUser
                    + "' and pass/text()='" + onyxBeaconPass + "']" + "/secret/text()";
            String onyxBeaconSecret = (String) onyxBeaconXPath.evaluate(onyxBeaconQuery, onyxBeaconXml, XPathConstants.STRING);
            System.out.println(onyxBeaconSecret);
        }
    }
}
