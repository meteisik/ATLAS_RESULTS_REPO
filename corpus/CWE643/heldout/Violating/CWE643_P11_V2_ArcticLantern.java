import java.util.HashMap;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P11_V2_ArcticLantern {

    public void runArcticLantern() throws XPathExpressionException {
        String data;
        data = null;
        for (int j = 0; j < 1; j++) {
            data = System.getenv("ARCTIC_LANTERN_ADD");
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE643_P11_V2_ArcticLanternSink()).sinkArcticLantern(dataHashMap);
    }
}

class CWE643_P11_V2_ArcticLanternSink {

    public void sinkArcticLantern(HashMap<Integer, String> dataHashMap) throws XPathExpressionException {
        String data = dataHashMap.get(2);
        String arcticLanternXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            arcticLanternXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            arcticLanternXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] arcticLanternTokens = data.split("||");
            if (arcticLanternTokens.length < 2) {
                return;
            }
            String arcticLanternUser = arcticLanternTokens[0];
            String arcticLanternPass = arcticLanternTokens[1];
            XPath arcticLanternXPath = XPathFactory.newInstance().newXPath();
            InputSource arcticLanternXml = new InputSource(arcticLanternXmlFile);
            String arcticLanternQuery = "//users/user[name/text()='" + arcticLanternUser
                    + "' and pass/text()='" + arcticLanternPass + "']" + "/secret/text()";
            String arcticLanternSecret = (String) arcticLanternXPath.evaluate(arcticLanternQuery, arcticLanternXml, XPathConstants.STRING);
            System.out.println(arcticLanternSecret);
        }
    }
}
