import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P03_V1_CrimsonBeacon {

    private void sinkCrimsonBeacon(String data) throws XPathExpressionException {
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

    public void runCrimsonBeacon() throws XPathExpressionException {
        String data;
        data = System.getenv("CRIMSON_BEACON_ADD");
        sinkCrimsonBeacon(data);
    }
}
