import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P03_V1_GoldenMantis {

    private void sinkGoldenMantis(String data) throws XPathExpressionException {
        String goldenMantisXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            goldenMantisXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            goldenMantisXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] goldenMantisTokens = data.split("||");
            if (goldenMantisTokens.length < 2) {
                return;
            }
            String goldenMantisUser = goldenMantisTokens[0];
            String goldenMantisPass = goldenMantisTokens[1];
            XPath goldenMantisXPath = XPathFactory.newInstance().newXPath();
            InputSource goldenMantisXml = new InputSource(goldenMantisXmlFile);
            String goldenMantisQuery = "//users/user[name/text()='" + goldenMantisUser
                    + "' and pass/text()='" + goldenMantisPass + "']" + "/secret/text()";
            String goldenMantisSecret = (String) goldenMantisXPath.evaluate(goldenMantisQuery, goldenMantisXml, XPathConstants.STRING);
            System.out.println(goldenMantisSecret);
        }
    }

    public void runGoldenMantis() throws XPathExpressionException {
        String data;
        data = System.getenv("GOLDEN_MANTIS_ADD");
        sinkGoldenMantis(data);
    }
}
