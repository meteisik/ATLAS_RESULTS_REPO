import java.util.HashMap;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P11_V1_ZephyrSignal {

    public void runZephyrSignal() throws XPathExpressionException {
        String data;
        data = System.getenv("ZEPHYR_SIGNAL_ADD");
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE643_P11_V1_ZephyrSignalSink()).sinkZephyrSignal(dataHashMap);
    }
}

class CWE643_P11_V1_ZephyrSignalSink {

    public void sinkZephyrSignal(HashMap<Integer, String> dataHashMap) throws XPathExpressionException {
        String data = dataHashMap.get(2);
        String zephyrSignalXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            zephyrSignalXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            zephyrSignalXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] zephyrSignalTokens = data.split("||");
            if (zephyrSignalTokens.length < 2) {
                return;
            }
            String zephyrSignalUser = zephyrSignalTokens[0];
            String zephyrSignalPass = zephyrSignalTokens[1];
            XPath zephyrSignalXPath = XPathFactory.newInstance().newXPath();
            InputSource zephyrSignalXml = new InputSource(zephyrSignalXmlFile);
            String zephyrSignalQuery = "//users/user[name/text()='" + zephyrSignalUser
                    + "' and pass/text()='" + zephyrSignalPass + "']" + "/secret/text()";
            String zephyrSignalSecret = (String) zephyrSignalXPath.evaluate(zephyrSignalQuery, zephyrSignalXml, XPathConstants.STRING);
            System.out.println(zephyrSignalSecret);
        }
    }
}
