import java.util.HashMap;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P11_V1_ZephyrQuartz {

    public void runZephyrQuartz() throws XPathExpressionException {
        String data;
        data = System.getenv("ZEPHYR_QUARTZ_ADD");
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE643_P11_V1_ZephyrQuartzSink()).sinkZephyrQuartz(dataHashMap);
    }
}

class CWE643_P11_V1_ZephyrQuartzSink {

    public void sinkZephyrQuartz(HashMap<Integer, String> dataHashMap) throws XPathExpressionException {
        String data = dataHashMap.get(2);
        String zephyrQuartzXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            zephyrQuartzXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            zephyrQuartzXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] zephyrQuartzTokens = data.split("||");
            if (zephyrQuartzTokens.length < 2) {
                return;
            }
            String zephyrQuartzUser = zephyrQuartzTokens[0];
            String zephyrQuartzPass = zephyrQuartzTokens[1];
            XPath zephyrQuartzXPath = XPathFactory.newInstance().newXPath();
            InputSource zephyrQuartzXml = new InputSource(zephyrQuartzXmlFile);
            String zephyrQuartzQuery = "//users/user[name/text()='" + zephyrQuartzUser
                    + "' and pass/text()='" + zephyrQuartzPass + "']" + "/secret/text()";
            String zephyrQuartzSecret = (String) zephyrQuartzXPath.evaluate(zephyrQuartzQuery, zephyrQuartzXml, XPathConstants.STRING);
            System.out.println(zephyrQuartzSecret);
        }
    }
}
