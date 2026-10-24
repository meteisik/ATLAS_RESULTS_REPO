import java.util.HashMap;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P11_V2_ArcticKestrelSafe {

    public void runArcticKestrel() throws XPathExpressionException {
        String data;
        while (true) {
            data = "foo";
            break;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE643_P11_V2_ArcticKestrelSafeSink()).sinkArcticKestrel(dataHashMap);
    }
}

class CWE643_P11_V2_ArcticKestrelSafeSink {

    public void sinkArcticKestrel(HashMap<Integer, String> dataHashMap) throws XPathExpressionException {
        String data = dataHashMap.get(2);
        String arcticKestrelXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            arcticKestrelXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            arcticKestrelXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] arcticKestrelTokens = data.split("||");
            if (arcticKestrelTokens.length < 2) {
                return;
            }
            String arcticKestrelUser = arcticKestrelTokens[0];
            String arcticKestrelPass = arcticKestrelTokens[1];
            XPath arcticKestrelXPath = XPathFactory.newInstance().newXPath();
            InputSource arcticKestrelXml = new InputSource(arcticKestrelXmlFile);
            String arcticKestrelQuery = "//users/user[name/text()='" + arcticKestrelUser
                    + "' and pass/text()='" + arcticKestrelPass + "']" + "/secret/text()";
            String arcticKestrelSecret = (String) arcticKestrelXPath.evaluate(arcticKestrelQuery, arcticKestrelXml, XPathConstants.STRING);
            System.out.println(arcticKestrelSecret);
        }
    }
}
