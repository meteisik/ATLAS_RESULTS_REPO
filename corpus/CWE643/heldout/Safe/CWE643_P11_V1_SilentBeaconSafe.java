import java.util.HashMap;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P11_V1_SilentBeaconSafe {

    public void runSilentBeacon() throws XPathExpressionException {
        String data;
        data = "foo";
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE643_P11_V1_SilentBeaconSafeSink()).sinkSilentBeacon(dataHashMap);
    }
}

class CWE643_P11_V1_SilentBeaconSafeSink {

    public void sinkSilentBeacon(HashMap<Integer, String> dataHashMap) throws XPathExpressionException {
        String data = dataHashMap.get(2);
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
