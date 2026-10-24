import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P03_V1_GoldenCascade {

    private void sinkGoldenCascade(String data) throws XPathExpressionException {
        String goldenCascadeXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            goldenCascadeXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            goldenCascadeXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] goldenCascadeTokens = data.split("||");
            if (goldenCascadeTokens.length < 2) {
                return;
            }
            String goldenCascadeUser = goldenCascadeTokens[0];
            String goldenCascadePass = goldenCascadeTokens[1];
            XPath goldenCascadeXPath = XPathFactory.newInstance().newXPath();
            InputSource goldenCascadeXml = new InputSource(goldenCascadeXmlFile);
            String goldenCascadeQuery = "//users/user[name/text()='" + goldenCascadeUser
                    + "' and pass/text()='" + goldenCascadePass + "']" + "/secret/text()";
            String goldenCascadeSecret = (String) goldenCascadeXPath.evaluate(goldenCascadeQuery, goldenCascadeXml, XPathConstants.STRING);
            System.out.println(goldenCascadeSecret);
        }
    }

    public void runGoldenCascade() throws XPathExpressionException {
        String data;
        data = System.getenv("GOLDEN_CASCADE_ADD");
        sinkGoldenCascade(data);
    }
}
