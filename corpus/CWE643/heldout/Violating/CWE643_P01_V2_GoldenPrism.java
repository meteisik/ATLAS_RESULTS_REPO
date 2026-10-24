import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P01_V2_GoldenPrism {

    public void runGoldenPrism() throws XPathExpressionException {
        String data;
        switch (7) {
        case 7:
            data = System.getenv("GOLDEN_PRISM_ADD");
            break;
        default:
            data = null;
            break;
        }
        String goldenPrismXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            goldenPrismXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            goldenPrismXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] goldenPrismTokens = data.split("||");
            if (goldenPrismTokens.length < 2) {
                return;
            }
            String goldenPrismUser = goldenPrismTokens[0];
            String goldenPrismPass = goldenPrismTokens[1];
            XPath goldenPrismXPath = XPathFactory.newInstance().newXPath();
            InputSource goldenPrismXml = new InputSource(goldenPrismXmlFile);
            String goldenPrismQuery = "//users/user[name/text()='" + goldenPrismUser
                    + "' and pass/text()='" + goldenPrismPass + "']" + "/secret/text()";
            String goldenPrismSecret = (String) goldenPrismXPath.evaluate(goldenPrismQuery, goldenPrismXml, XPathConstants.STRING);
            System.out.println(goldenPrismSecret);
        }
    }
}
