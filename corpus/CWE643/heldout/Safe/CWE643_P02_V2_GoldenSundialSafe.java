import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P02_V2_GoldenSundialSafe {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    public void runGoldenSundial() throws XPathExpressionException {
        String dataCopy;
        {
            String data;
            if (PRIVATE_STATIC_FINAL_TRUE) {
                data = "foo";
            } else {
                data = null;
            }
            dataCopy = data;
        }
        {
            String data = dataCopy;
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
    }
}
