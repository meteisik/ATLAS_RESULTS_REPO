import java.util.HashMap;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P11_V2_CobaltKestrelSafe {

    public void runCobaltKestrel() throws XPathExpressionException {
        String data;
        data = null;
        for (int j = 0; j < 1; j++) {
            data = "foo";
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE643_P11_V2_CobaltKestrelSafeSink()).sinkCobaltKestrel(dataHashMap);
    }
}

class CWE643_P11_V2_CobaltKestrelSafeSink {

    public void sinkCobaltKestrel(HashMap<Integer, String> dataHashMap) throws XPathExpressionException {
        String data = dataHashMap.get(2);
        String cobaltKestrelXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            cobaltKestrelXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            cobaltKestrelXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] cobaltKestrelTokens = data.split("||");
            if (cobaltKestrelTokens.length < 2) {
                return;
            }
            String cobaltKestrelUser = cobaltKestrelTokens[0];
            String cobaltKestrelPass = cobaltKestrelTokens[1];
            XPath cobaltKestrelXPath = XPathFactory.newInstance().newXPath();
            InputSource cobaltKestrelXml = new InputSource(cobaltKestrelXmlFile);
            String cobaltKestrelQuery = "//users/user[name/text()='" + cobaltKestrelUser
                    + "' and pass/text()='" + cobaltKestrelPass + "']" + "/secret/text()";
            String cobaltKestrelSecret = (String) cobaltKestrelXPath.evaluate(cobaltKestrelQuery, cobaltKestrelXml, XPathConstants.STRING);
            System.out.println(cobaltKestrelSecret);
        }
    }
}
