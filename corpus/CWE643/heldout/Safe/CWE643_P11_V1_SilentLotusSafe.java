import java.util.HashMap;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P11_V1_SilentLotusSafe {

    public void runSilentLotus() throws XPathExpressionException {
        String data;
        data = "foo";
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE643_P11_V1_SilentLotusSafeSink()).sinkSilentLotus(dataHashMap);
    }
}

class CWE643_P11_V1_SilentLotusSafeSink {

    public void sinkSilentLotus(HashMap<Integer, String> dataHashMap) throws XPathExpressionException {
        String data = dataHashMap.get(2);
        String silentLotusXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            silentLotusXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            silentLotusXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] silentLotusTokens = data.split("||");
            if (silentLotusTokens.length < 2) {
                return;
            }
            String silentLotusUser = silentLotusTokens[0];
            String silentLotusPass = silentLotusTokens[1];
            XPath silentLotusXPath = XPathFactory.newInstance().newXPath();
            InputSource silentLotusXml = new InputSource(silentLotusXmlFile);
            String silentLotusQuery = "//users/user[name/text()='" + silentLotusUser
                    + "' and pass/text()='" + silentLotusPass + "']" + "/secret/text()";
            String silentLotusSecret = (String) silentLotusXPath.evaluate(silentLotusQuery, silentLotusXml, XPathConstants.STRING);
            System.out.println(silentLotusSecret);
        }
    }
}
