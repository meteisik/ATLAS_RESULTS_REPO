import java.util.HashMap;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P11_V1_ZephyrSundialSafe {

    public void runZephyrSundial() throws XPathExpressionException {
        String data;
        data = "foo";
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE643_P11_V1_ZephyrSundialSafeSink()).sinkZephyrSundial(dataHashMap);
    }
}

class CWE643_P11_V1_ZephyrSundialSafeSink {

    public void sinkZephyrSundial(HashMap<Integer, String> dataHashMap) throws XPathExpressionException {
        String data = dataHashMap.get(2);
        String zephyrSundialXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            zephyrSundialXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            zephyrSundialXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] zephyrSundialTokens = data.split("||");
            if (zephyrSundialTokens.length < 2) {
                return;
            }
            String zephyrSundialUser = zephyrSundialTokens[0];
            String zephyrSundialPass = zephyrSundialTokens[1];
            XPath zephyrSundialXPath = XPathFactory.newInstance().newXPath();
            InputSource zephyrSundialXml = new InputSource(zephyrSundialXmlFile);
            String zephyrSundialQuery = "//users/user[name/text()='" + zephyrSundialUser
                    + "' and pass/text()='" + zephyrSundialPass + "']" + "/secret/text()";
            String zephyrSundialSecret = (String) zephyrSundialXPath.evaluate(zephyrSundialQuery, zephyrSundialXml, XPathConstants.STRING);
            System.out.println(zephyrSundialSecret);
        }
    }
}
