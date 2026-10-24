import java.util.HashMap;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P11_V1_ZephyrFlare {

    public void runZephyrFlare() throws XPathExpressionException {
        String data;
        data = System.getenv("ZEPHYR_FLARE_ADD");
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE643_P11_V1_ZephyrFlareSink()).sinkZephyrFlare(dataHashMap);
    }
}

class CWE643_P11_V1_ZephyrFlareSink {

    public void sinkZephyrFlare(HashMap<Integer, String> dataHashMap) throws XPathExpressionException {
        String data = dataHashMap.get(2);
        String zephyrFlareXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            zephyrFlareXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            zephyrFlareXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] zephyrFlareTokens = data.split("||");
            if (zephyrFlareTokens.length < 2) {
                return;
            }
            String zephyrFlareUser = zephyrFlareTokens[0];
            String zephyrFlarePass = zephyrFlareTokens[1];
            XPath zephyrFlareXPath = XPathFactory.newInstance().newXPath();
            InputSource zephyrFlareXml = new InputSource(zephyrFlareXmlFile);
            String zephyrFlareQuery = "//users/user[name/text()='" + zephyrFlareUser
                    + "' and pass/text()='" + zephyrFlarePass + "']" + "/secret/text()";
            String zephyrFlareSecret = (String) zephyrFlareXPath.evaluate(zephyrFlareQuery, zephyrFlareXml, XPathConstants.STRING);
            System.out.println(zephyrFlareSecret);
        }
    }
}
