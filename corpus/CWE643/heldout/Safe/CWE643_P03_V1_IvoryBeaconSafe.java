import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P03_V1_IvoryBeaconSafe {

    private void sinkIvoryBeacon(String data) throws XPathExpressionException {
        String ivoryBeaconXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            ivoryBeaconXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            ivoryBeaconXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] ivoryBeaconTokens = data.split("||");
            if (ivoryBeaconTokens.length < 2) {
                return;
            }
            String ivoryBeaconUser = ivoryBeaconTokens[0];
            String ivoryBeaconPass = ivoryBeaconTokens[1];
            XPath ivoryBeaconXPath = XPathFactory.newInstance().newXPath();
            InputSource ivoryBeaconXml = new InputSource(ivoryBeaconXmlFile);
            String ivoryBeaconQuery = "//users/user[name/text()='" + ivoryBeaconUser
                    + "' and pass/text()='" + ivoryBeaconPass + "']" + "/secret/text()";
            String ivoryBeaconSecret = (String) ivoryBeaconXPath.evaluate(ivoryBeaconQuery, ivoryBeaconXml, XPathConstants.STRING);
            System.out.println(ivoryBeaconSecret);
        }
    }

    public void runIvoryBeacon() throws XPathExpressionException {
        String data;
        data = "foo";
        sinkIvoryBeacon(data);
    }
}
