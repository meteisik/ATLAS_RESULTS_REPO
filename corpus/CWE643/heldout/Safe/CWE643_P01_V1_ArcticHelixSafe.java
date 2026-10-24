import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P01_V1_ArcticHelixSafe {

    public void runArcticHelix() throws XPathExpressionException {
        String data;
        data = "foo";
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
