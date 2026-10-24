import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P05_V1_GoldenSundial {

    private String goldenSundialData;

    private void sinkGoldenSundial() throws XPathExpressionException {
        String data = goldenSundialData;
        String goldenSundialXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            goldenSundialXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            goldenSundialXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] goldenSundialTokens = data.split("||");
            if (goldenSundialTokens.length < 2) {
                return;
            }
            String goldenSundialUser = goldenSundialTokens[0];
            String goldenSundialPass = goldenSundialTokens[1];
            XPath goldenSundialXPath = XPathFactory.newInstance().newXPath();
            InputSource goldenSundialXml = new InputSource(goldenSundialXmlFile);
            String goldenSundialQuery = "//users/user[name/text()='" + goldenSundialUser
                    + "' and pass/text()='" + goldenSundialPass + "']" + "/secret/text()";
            String goldenSundialSecret = (String) goldenSundialXPath.evaluate(goldenSundialQuery, goldenSundialXml, XPathConstants.STRING);
            System.out.println(goldenSundialSecret);
        }
    }

    public void runGoldenSundial() throws XPathExpressionException {
        String data;
        data = System.getenv("GOLDEN_SUNDIAL_ADD");
        goldenSundialData = data;
        sinkGoldenSundial();
    }
}
