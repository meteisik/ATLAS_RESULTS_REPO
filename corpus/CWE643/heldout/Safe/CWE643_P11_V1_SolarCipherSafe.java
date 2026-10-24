import java.util.HashMap;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P11_V1_SolarCipherSafe {

    public void runSolarCipher() throws XPathExpressionException {
        String data;
        data = "foo";
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE643_P11_V1_SolarCipherSafeSink()).sinkSolarCipher(dataHashMap);
    }
}

class CWE643_P11_V1_SolarCipherSafeSink {

    public void sinkSolarCipher(HashMap<Integer, String> dataHashMap) throws XPathExpressionException {
        String data = dataHashMap.get(2);
        String solarCipherXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            solarCipherXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            solarCipherXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] solarCipherTokens = data.split("||");
            if (solarCipherTokens.length < 2) {
                return;
            }
            String solarCipherUser = solarCipherTokens[0];
            String solarCipherPass = solarCipherTokens[1];
            XPath solarCipherXPath = XPathFactory.newInstance().newXPath();
            InputSource solarCipherXml = new InputSource(solarCipherXmlFile);
            String solarCipherQuery = "//users/user[name/text()='" + solarCipherUser
                    + "' and pass/text()='" + solarCipherPass + "']" + "/secret/text()";
            String solarCipherSecret = (String) solarCipherXPath.evaluate(solarCipherQuery, solarCipherXml, XPathConstants.STRING);
            System.out.println(solarCipherSecret);
        }
    }
}
