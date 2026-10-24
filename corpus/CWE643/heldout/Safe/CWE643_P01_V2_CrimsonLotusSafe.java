import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P01_V2_CrimsonLotusSafe {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    public void runCrimsonLotus() throws XPathExpressionException {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = "foo";
        } else {
            data = null;
        }
        String crimsonLotusXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            crimsonLotusXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            crimsonLotusXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] crimsonLotusTokens = data.split("||");
            if (crimsonLotusTokens.length < 2) {
                return;
            }
            String crimsonLotusUser = crimsonLotusTokens[0];
            String crimsonLotusPass = crimsonLotusTokens[1];
            XPath crimsonLotusXPath = XPathFactory.newInstance().newXPath();
            InputSource crimsonLotusXml = new InputSource(crimsonLotusXmlFile);
            String crimsonLotusQuery = "//users/user[name/text()='" + crimsonLotusUser
                    + "' and pass/text()='" + crimsonLotusPass + "']" + "/secret/text()";
            String crimsonLotusSecret = (String) crimsonLotusXPath.evaluate(crimsonLotusQuery, crimsonLotusXml, XPathConstants.STRING);
            System.out.println(crimsonLotusSecret);
        }
    }
}
