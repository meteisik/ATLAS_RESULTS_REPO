import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P02_V1_ArcticLantern {

    public void runArcticLantern() throws XPathExpressionException {
        String dataCopy;
        {
            String data;
            data = System.getenv("ARCTIC_LANTERN_ADD");
            dataCopy = data;
        }
        {
            String data = dataCopy;
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
}
