import java.util.HashMap;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P11_V2_ArcticHarbor {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void runArcticHarbor() throws XPathExpressionException {
        String data;
        if (IO.staticFive == 5) {
            data = System.getenv("ARCTIC_HARBOR_ADD");
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE643_P11_V2_ArcticHarborSink()).sinkArcticHarbor(dataHashMap);
    }
}

class CWE643_P11_V2_ArcticHarborSink {

    public void sinkArcticHarbor(HashMap<Integer, String> dataHashMap) throws XPathExpressionException {
        String data = dataHashMap.get(2);
        String arcticHarborXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            arcticHarborXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            arcticHarborXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] arcticHarborTokens = data.split("||");
            if (arcticHarborTokens.length < 2) {
                return;
            }
            String arcticHarborUser = arcticHarborTokens[0];
            String arcticHarborPass = arcticHarborTokens[1];
            XPath arcticHarborXPath = XPathFactory.newInstance().newXPath();
            InputSource arcticHarborXml = new InputSource(arcticHarborXmlFile);
            String arcticHarborQuery = "//users/user[name/text()='" + arcticHarborUser
                    + "' and pass/text()='" + arcticHarborPass + "']" + "/secret/text()";
            String arcticHarborSecret = (String) arcticHarborXPath.evaluate(arcticHarborQuery, arcticHarborXml, XPathConstants.STRING);
            System.out.println(arcticHarborSecret);
        }
    }
}
