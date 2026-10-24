import java.util.HashMap;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P11_V2_CrimsonBeacon {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    public void runCrimsonBeacon() throws XPathExpressionException {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = System.getenv("CRIMSON_BEACON_ADD");
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE643_P11_V2_CrimsonBeaconSink()).sinkCrimsonBeacon(dataHashMap);
    }
}

class CWE643_P11_V2_CrimsonBeaconSink {

    public void sinkCrimsonBeacon(HashMap<Integer, String> dataHashMap) throws XPathExpressionException {
        String data = dataHashMap.get(2);
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
