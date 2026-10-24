import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P03_V1_GoldenGlint {

    private void sinkGoldenGlint(String data) throws XPathExpressionException {
        String goldenGlintXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            goldenGlintXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            goldenGlintXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] goldenGlintTokens = data.split("||");
            if (goldenGlintTokens.length < 2) {
                return;
            }
            String goldenGlintUser = goldenGlintTokens[0];
            String goldenGlintPass = goldenGlintTokens[1];
            XPath goldenGlintXPath = XPathFactory.newInstance().newXPath();
            InputSource goldenGlintXml = new InputSource(goldenGlintXmlFile);
            String goldenGlintQuery = "//users/user[name/text()='" + goldenGlintUser
                    + "' and pass/text()='" + goldenGlintPass + "']" + "/secret/text()";
            String goldenGlintSecret = (String) goldenGlintXPath.evaluate(goldenGlintQuery, goldenGlintXml, XPathConstants.STRING);
            System.out.println(goldenGlintSecret);
        }
    }

    public void runGoldenGlint() throws XPathExpressionException {
        String data;
        data = System.getenv("GOLDEN_GLINT_ADD");
        sinkGoldenGlint(data);
    }
}
