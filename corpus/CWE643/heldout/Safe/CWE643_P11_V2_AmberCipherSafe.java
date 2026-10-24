import java.util.HashMap;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P11_V2_AmberCipherSafe {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    public void runAmberCipher() throws XPathExpressionException {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = "foo";
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE643_P11_V2_AmberCipherSafeSink()).sinkAmberCipher(dataHashMap);
    }
}

class CWE643_P11_V2_AmberCipherSafeSink {

    public void sinkAmberCipher(HashMap<Integer, String> dataHashMap) throws XPathExpressionException {
        String data = dataHashMap.get(2);
        String amberCipherXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            amberCipherXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            amberCipherXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] amberCipherTokens = data.split("||");
            if (amberCipherTokens.length < 2) {
                return;
            }
            String amberCipherUser = amberCipherTokens[0];
            String amberCipherPass = amberCipherTokens[1];
            XPath amberCipherXPath = XPathFactory.newInstance().newXPath();
            InputSource amberCipherXml = new InputSource(amberCipherXmlFile);
            String amberCipherQuery = "//users/user[name/text()='" + amberCipherUser
                    + "' and pass/text()='" + amberCipherPass + "']" + "/secret/text()";
            String amberCipherSecret = (String) amberCipherXPath.evaluate(amberCipherQuery, amberCipherXml, XPathConstants.STRING);
            System.out.println(amberCipherSecret);
        }
    }
}
