import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P03_V1_GoldenFlare {

    private void sinkGoldenFlare(String data) throws XPathExpressionException {
        String goldenFlareXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            goldenFlareXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            goldenFlareXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] goldenFlareTokens = data.split("||");
            if (goldenFlareTokens.length < 2) {
                return;
            }
            String goldenFlareUser = goldenFlareTokens[0];
            String goldenFlarePass = goldenFlareTokens[1];
            XPath goldenFlareXPath = XPathFactory.newInstance().newXPath();
            InputSource goldenFlareXml = new InputSource(goldenFlareXmlFile);
            String goldenFlareQuery = "//users/user[name/text()='" + goldenFlareUser
                    + "' and pass/text()='" + goldenFlarePass + "']" + "/secret/text()";
            String goldenFlareSecret = (String) goldenFlareXPath.evaluate(goldenFlareQuery, goldenFlareXml, XPathConstants.STRING);
            System.out.println(goldenFlareSecret);
        }
    }

    public void runGoldenFlare() throws XPathExpressionException {
        String data;
        data = System.getenv("GOLDEN_FLARE_ADD");
        sinkGoldenFlare(data);
    }
}
