import java.util.HashMap;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P11_V1_ZephyrGlint {

    public void runZephyrGlint() throws XPathExpressionException {
        String data;
        data = System.getenv("ZEPHYR_GLINT_ADD");
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE643_P11_V1_ZephyrGlintSink()).sinkZephyrGlint(dataHashMap);
    }
}

class CWE643_P11_V1_ZephyrGlintSink {

    public void sinkZephyrGlint(HashMap<Integer, String> dataHashMap) throws XPathExpressionException {
        String data = dataHashMap.get(2);
        String zephyrGlintXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            zephyrGlintXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            zephyrGlintXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] zephyrGlintTokens = data.split("||");
            if (zephyrGlintTokens.length < 2) {
                return;
            }
            String zephyrGlintUser = zephyrGlintTokens[0];
            String zephyrGlintPass = zephyrGlintTokens[1];
            XPath zephyrGlintXPath = XPathFactory.newInstance().newXPath();
            InputSource zephyrGlintXml = new InputSource(zephyrGlintXmlFile);
            String zephyrGlintQuery = "//users/user[name/text()='" + zephyrGlintUser
                    + "' and pass/text()='" + zephyrGlintPass + "']" + "/secret/text()";
            String zephyrGlintSecret = (String) zephyrGlintXPath.evaluate(zephyrGlintQuery, zephyrGlintXml, XPathConstants.STRING);
            System.out.println(zephyrGlintSecret);
        }
    }
}
