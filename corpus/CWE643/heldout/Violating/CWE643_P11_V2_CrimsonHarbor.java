import java.util.HashMap;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P11_V2_CrimsonHarbor {
    private static boolean privateReturnsTrue() { return true; }

    public void runCrimsonHarbor() throws XPathExpressionException {
        String data;
        if (privateReturnsTrue()) {
            data = System.getenv("CRIMSON_HARBOR_ADD");
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE643_P11_V2_CrimsonHarborSink()).sinkCrimsonHarbor(dataHashMap);
    }
}

class CWE643_P11_V2_CrimsonHarborSink {

    public void sinkCrimsonHarbor(HashMap<Integer, String> dataHashMap) throws XPathExpressionException {
        String data = dataHashMap.get(2);
        String crimsonHarborXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            crimsonHarborXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            crimsonHarborXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] crimsonHarborTokens = data.split("||");
            if (crimsonHarborTokens.length < 2) {
                return;
            }
            String crimsonHarborUser = crimsonHarborTokens[0];
            String crimsonHarborPass = crimsonHarborTokens[1];
            XPath crimsonHarborXPath = XPathFactory.newInstance().newXPath();
            InputSource crimsonHarborXml = new InputSource(crimsonHarborXmlFile);
            String crimsonHarborQuery = "//users/user[name/text()='" + crimsonHarborUser
                    + "' and pass/text()='" + crimsonHarborPass + "']" + "/secret/text()";
            String crimsonHarborSecret = (String) crimsonHarborXPath.evaluate(crimsonHarborQuery, crimsonHarborXml, XPathConstants.STRING);
            System.out.println(crimsonHarborSecret);
        }
    }
}
