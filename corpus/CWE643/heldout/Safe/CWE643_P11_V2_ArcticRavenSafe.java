import java.util.HashMap;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P11_V2_ArcticRavenSafe {
    private static boolean privateTrue = true;

    public void runArcticRaven() throws XPathExpressionException {
        String data;
        if (privateTrue) {
            data = "foo";
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE643_P11_V2_ArcticRavenSafeSink()).sinkArcticRaven(dataHashMap);
    }
}

class CWE643_P11_V2_ArcticRavenSafeSink {

    public void sinkArcticRaven(HashMap<Integer, String> dataHashMap) throws XPathExpressionException {
        String data = dataHashMap.get(2);
        String arcticRavenXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            arcticRavenXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            arcticRavenXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] arcticRavenTokens = data.split("||");
            if (arcticRavenTokens.length < 2) {
                return;
            }
            String arcticRavenUser = arcticRavenTokens[0];
            String arcticRavenPass = arcticRavenTokens[1];
            XPath arcticRavenXPath = XPathFactory.newInstance().newXPath();
            InputSource arcticRavenXml = new InputSource(arcticRavenXmlFile);
            String arcticRavenQuery = "//users/user[name/text()='" + arcticRavenUser
                    + "' and pass/text()='" + arcticRavenPass + "']" + "/secret/text()";
            String arcticRavenSecret = (String) arcticRavenXPath.evaluate(arcticRavenQuery, arcticRavenXml, XPathConstants.STRING);
            System.out.println(arcticRavenSecret);
        }
    }
}
