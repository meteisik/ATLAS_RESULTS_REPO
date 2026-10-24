import java.util.HashMap;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P11_V2_ArcticBeacon {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void runArcticBeacon() throws XPathExpressionException {
        String data;
        if (IO.staticReturnsTrue()) {
            data = System.getenv("ARCTIC_BEACON_ADD");
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE643_P11_V2_ArcticBeaconSink()).sinkArcticBeacon(dataHashMap);
    }
}

class CWE643_P11_V2_ArcticBeaconSink {

    public void sinkArcticBeacon(HashMap<Integer, String> dataHashMap) throws XPathExpressionException {
        String data = dataHashMap.get(2);
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
