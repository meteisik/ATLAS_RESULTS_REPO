import java.util.HashMap;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P11_V1_ZephyrCipher {

    public void runZephyrCipher() throws XPathExpressionException {
        String data;
        data = System.getenv("ZEPHYR_CIPHER_ADD");
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE643_P11_V1_ZephyrCipherSink()).sinkZephyrCipher(dataHashMap);
    }
}

class CWE643_P11_V1_ZephyrCipherSink {

    public void sinkZephyrCipher(HashMap<Integer, String> dataHashMap) throws XPathExpressionException {
        String data = dataHashMap.get(2);
        String zephyrCipherXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            zephyrCipherXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            zephyrCipherXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] zephyrCipherTokens = data.split("||");
            if (zephyrCipherTokens.length < 2) {
                return;
            }
            String zephyrCipherUser = zephyrCipherTokens[0];
            String zephyrCipherPass = zephyrCipherTokens[1];
            XPath zephyrCipherXPath = XPathFactory.newInstance().newXPath();
            InputSource zephyrCipherXml = new InputSource(zephyrCipherXmlFile);
            String zephyrCipherQuery = "//users/user[name/text()='" + zephyrCipherUser
                    + "' and pass/text()='" + zephyrCipherPass + "']" + "/secret/text()";
            String zephyrCipherSecret = (String) zephyrCipherXPath.evaluate(zephyrCipherQuery, zephyrCipherXml, XPathConstants.STRING);
            System.out.println(zephyrCipherSecret);
        }
    }
}
