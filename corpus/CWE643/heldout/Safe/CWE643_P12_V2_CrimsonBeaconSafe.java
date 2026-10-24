import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P12_V2_CrimsonBeaconSafe {
    private static boolean privateReturnsTrue() { return true; }

    public void runCrimsonBeacon() throws XPathExpressionException {
        String data;
        if (privateReturnsTrue()) {
            data = "foo";
        } else {
            data = null;
        }
        CWE643_P12_V2_CrimsonBeaconSafeBase baseObject = new CWE643_P12_V2_CrimsonBeaconSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE643_P12_V2_CrimsonBeaconSafeBase {

    public abstract void action(String data) throws XPathExpressionException;
}

class CWE643_P12_V2_CrimsonBeaconSafeSink extends CWE643_P12_V2_CrimsonBeaconSafeBase {

    public void action(String data) throws XPathExpressionException {
        String crimsonBeaconXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            crimsonBeaconXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            crimsonBeaconXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] crimsonBeaconTokens = data.split("||");
            if (crimsonBeaconTokens.length < 2) {
                return;
            }
            String crimsonBeaconUser = crimsonBeaconTokens[0];
            String crimsonBeaconPass = crimsonBeaconTokens[1];
            XPath crimsonBeaconXPath = XPathFactory.newInstance().newXPath();
            InputSource crimsonBeaconXml = new InputSource(crimsonBeaconXmlFile);
            String crimsonBeaconQuery = "//users/user[name/text()='" + crimsonBeaconUser
                    + "' and pass/text()='" + crimsonBeaconPass + "']" + "/secret/text()";
            String crimsonBeaconSecret = (String) crimsonBeaconXPath.evaluate(crimsonBeaconQuery, crimsonBeaconXml, XPathConstants.STRING);
            System.out.println(crimsonBeaconSecret);
        }
    }
}
