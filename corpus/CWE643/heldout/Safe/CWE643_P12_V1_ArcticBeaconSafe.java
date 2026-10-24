import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P12_V1_ArcticBeaconSafe {

    public void runArcticBeacon() throws XPathExpressionException {
        String data;
        data = "foo";
        CWE643_P12_V1_ArcticBeaconSafeBase baseObject = new CWE643_P12_V1_ArcticBeaconSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE643_P12_V1_ArcticBeaconSafeBase {

    public abstract void action(String data) throws XPathExpressionException;
}

class CWE643_P12_V1_ArcticBeaconSafeSink extends CWE643_P12_V1_ArcticBeaconSafeBase {

    public void action(String data) throws XPathExpressionException {
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
