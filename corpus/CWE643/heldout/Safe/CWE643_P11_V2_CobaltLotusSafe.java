import java.util.HashMap;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P11_V2_CobaltLotusSafe {

    public void runCobaltLotus() throws XPathExpressionException {
        String data;
        if (5 == 5) {
            data = "foo";
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE643_P11_V2_CobaltLotusSafeSink()).sinkCobaltLotus(dataHashMap);
    }
}

class CWE643_P11_V2_CobaltLotusSafeSink {

    public void sinkCobaltLotus(HashMap<Integer, String> dataHashMap) throws XPathExpressionException {
        String data = dataHashMap.get(2);
        String cobaltLotusXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            cobaltLotusXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            cobaltLotusXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] cobaltLotusTokens = data.split("||");
            if (cobaltLotusTokens.length < 2) {
                return;
            }
            String cobaltLotusUser = cobaltLotusTokens[0];
            String cobaltLotusPass = cobaltLotusTokens[1];
            XPath cobaltLotusXPath = XPathFactory.newInstance().newXPath();
            InputSource cobaltLotusXml = new InputSource(cobaltLotusXmlFile);
            String cobaltLotusQuery = "//users/user[name/text()='" + cobaltLotusUser
                    + "' and pass/text()='" + cobaltLotusPass + "']" + "/secret/text()";
            String cobaltLotusSecret = (String) cobaltLotusXPath.evaluate(cobaltLotusQuery, cobaltLotusXml, XPathConstants.STRING);
            System.out.println(cobaltLotusSecret);
        }
    }
}
