import java.util.HashMap;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P11_V1_SilentKestrelSafe {

    public void runSilentKestrel() throws XPathExpressionException {
        String data;
        data = "foo";
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE643_P11_V1_SilentKestrelSafeSink()).sinkSilentKestrel(dataHashMap);
    }
}

class CWE643_P11_V1_SilentKestrelSafeSink {

    public void sinkSilentKestrel(HashMap<Integer, String> dataHashMap) throws XPathExpressionException {
        String data = dataHashMap.get(2);
        String silentKestrelXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            silentKestrelXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            silentKestrelXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] silentKestrelTokens = data.split("||");
            if (silentKestrelTokens.length < 2) {
                return;
            }
            String silentKestrelUser = silentKestrelTokens[0];
            String silentKestrelPass = silentKestrelTokens[1];
            XPath silentKestrelXPath = XPathFactory.newInstance().newXPath();
            InputSource silentKestrelXml = new InputSource(silentKestrelXmlFile);
            String silentKestrelQuery = "//users/user[name/text()='" + silentKestrelUser
                    + "' and pass/text()='" + silentKestrelPass + "']" + "/secret/text()";
            String silentKestrelSecret = (String) silentKestrelXPath.evaluate(silentKestrelQuery, silentKestrelXml, XPathConstants.STRING);
            System.out.println(silentKestrelSecret);
        }
    }
}
