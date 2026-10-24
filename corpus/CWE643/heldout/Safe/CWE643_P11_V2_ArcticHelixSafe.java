import java.util.HashMap;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P11_V2_ArcticHelixSafe {

    public void runArcticHelix() throws XPathExpressionException {
        String data;
        switch (7) {
        case 7:
            data = "foo";
            break;
        default:
            data = null;
            break;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE643_P11_V2_ArcticHelixSafeSink()).sinkArcticHelix(dataHashMap);
    }
}

class CWE643_P11_V2_ArcticHelixSafeSink {

    public void sinkArcticHelix(HashMap<Integer, String> dataHashMap) throws XPathExpressionException {
        String data = dataHashMap.get(2);
        String arcticHelixXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            arcticHelixXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            arcticHelixXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] arcticHelixTokens = data.split("||");
            if (arcticHelixTokens.length < 2) {
                return;
            }
            String arcticHelixUser = arcticHelixTokens[0];
            String arcticHelixPass = arcticHelixTokens[1];
            XPath arcticHelixXPath = XPathFactory.newInstance().newXPath();
            InputSource arcticHelixXml = new InputSource(arcticHelixXmlFile);
            String arcticHelixQuery = "//users/user[name/text()='" + arcticHelixUser
                    + "' and pass/text()='" + arcticHelixPass + "']" + "/secret/text()";
            String arcticHelixSecret = (String) arcticHelixXPath.evaluate(arcticHelixQuery, arcticHelixXml, XPathConstants.STRING);
            System.out.println(arcticHelixSecret);
        }
    }
}
