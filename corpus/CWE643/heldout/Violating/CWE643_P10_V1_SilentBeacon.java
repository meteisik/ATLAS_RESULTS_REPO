import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P10_V1_SilentBeacon {

    public static String data;

    public void runSilentBeacon() throws XPathExpressionException {
        data = System.getenv("SILENT_BEACON_ADD");
        (new CWE643_P10_V1_SilentBeaconSink()).sinkSilentBeacon();
    }
}

class CWE643_P10_V1_SilentBeaconSink {

    public void sinkSilentBeacon() throws XPathExpressionException {
        String data = CWE643_P10_V1_SilentBeacon.data;
        String silentBeaconXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            silentBeaconXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            silentBeaconXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] silentBeaconTokens = data.split("||");
            if (silentBeaconTokens.length < 2) {
                return;
            }
            String silentBeaconUser = silentBeaconTokens[0];
            String silentBeaconPass = silentBeaconTokens[1];
            XPath silentBeaconXPath = XPathFactory.newInstance().newXPath();
            InputSource silentBeaconXml = new InputSource(silentBeaconXmlFile);
            String silentBeaconQuery = "//users/user[name/text()='" + silentBeaconUser
                    + "' and pass/text()='" + silentBeaconPass + "']" + "/secret/text()";
            String silentBeaconSecret = (String) silentBeaconXPath.evaluate(silentBeaconQuery, silentBeaconXml, XPathConstants.STRING);
            System.out.println(silentBeaconSecret);
        }
    }
}
