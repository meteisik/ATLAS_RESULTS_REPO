import java.util.HashMap;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P11_V2_AmberAuroraSafe {

    public void runAmberAurora() throws XPathExpressionException {
        String data;
        if (true) {
            data = "foo";
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE643_P11_V2_AmberAuroraSafeSink()).sinkAmberAurora(dataHashMap);
    }
}

class CWE643_P11_V2_AmberAuroraSafeSink {

    public void sinkAmberAurora(HashMap<Integer, String> dataHashMap) throws XPathExpressionException {
        String data = dataHashMap.get(2);
        String amberAuroraXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            amberAuroraXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            amberAuroraXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] amberAuroraTokens = data.split("||");
            if (amberAuroraTokens.length < 2) {
                return;
            }
            String amberAuroraUser = amberAuroraTokens[0];
            String amberAuroraPass = amberAuroraTokens[1];
            XPath amberAuroraXPath = XPathFactory.newInstance().newXPath();
            InputSource amberAuroraXml = new InputSource(amberAuroraXmlFile);
            String amberAuroraQuery = "//users/user[name/text()='" + amberAuroraUser
                    + "' and pass/text()='" + amberAuroraPass + "']" + "/secret/text()";
            String amberAuroraSecret = (String) amberAuroraXPath.evaluate(amberAuroraQuery, amberAuroraXml, XPathConstants.STRING);
            System.out.println(amberAuroraSecret);
        }
    }
}
