import java.util.HashMap;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P11_V2_ArcticLotusSafe {

    public void runArcticLotus() throws XPathExpressionException {
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
        (new CWE643_P11_V2_ArcticLotusSafeSink()).sinkArcticLotus(dataHashMap);
    }
}

class CWE643_P11_V2_ArcticLotusSafeSink {

    public void sinkArcticLotus(HashMap<Integer, String> dataHashMap) throws XPathExpressionException {
        String data = dataHashMap.get(2);
        String arcticLotusXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            arcticLotusXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            arcticLotusXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] arcticLotusTokens = data.split("||");
            if (arcticLotusTokens.length < 2) {
                return;
            }
            String arcticLotusUser = arcticLotusTokens[0];
            String arcticLotusPass = arcticLotusTokens[1];
            XPath arcticLotusXPath = XPathFactory.newInstance().newXPath();
            InputSource arcticLotusXml = new InputSource(arcticLotusXmlFile);
            String arcticLotusQuery = "//users/user[name/text()='" + arcticLotusUser
                    + "' and pass/text()='" + arcticLotusPass + "']" + "/secret/text()";
            String arcticLotusSecret = (String) arcticLotusXPath.evaluate(arcticLotusQuery, arcticLotusXml, XPathConstants.STRING);
            System.out.println(arcticLotusSecret);
        }
    }
}
