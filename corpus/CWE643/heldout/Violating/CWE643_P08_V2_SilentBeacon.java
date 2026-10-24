import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P08_V2_SilentBeacon {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    public void runSilentBeacon() throws XPathExpressionException {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = System.getenv("SILENT_BEACON_ADD");
        } else {
            data = null;
        }
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE643_P08_V2_SilentBeaconSink()).sinkSilentBeacon(dataArray);
    }
}

class CWE643_P08_V2_SilentBeaconSink {

    public void sinkSilentBeacon(String[] dataArray) throws XPathExpressionException {
        String data = dataArray[2];
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
