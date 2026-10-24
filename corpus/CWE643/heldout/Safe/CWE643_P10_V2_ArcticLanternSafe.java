import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P10_V2_ArcticLanternSafe {

    public static String data;

    public void runArcticLantern() throws XPathExpressionException {
        switch (7) {
        case 7:
            data = "foo";
            break;
        default:
            data = null;
            break;
        }
        (new CWE643_P10_V2_ArcticLanternSafeSink()).sinkArcticLantern();
    }
}

class CWE643_P10_V2_ArcticLanternSafeSink {

    public void sinkArcticLantern() throws XPathExpressionException {
        String data = CWE643_P10_V2_ArcticLanternSafe.data;
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
