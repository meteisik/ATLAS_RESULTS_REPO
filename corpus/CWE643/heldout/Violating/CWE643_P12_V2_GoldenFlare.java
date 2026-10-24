import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P12_V2_GoldenFlare {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    public void runGoldenFlare() throws XPathExpressionException {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = System.getenv("GOLDEN_FLARE_ADD");
        } else {
            data = null;
        }
        CWE643_P12_V2_GoldenFlareBase baseObject = new CWE643_P12_V2_GoldenFlareSink();
        baseObject.action(data);
    }
}

abstract class CWE643_P12_V2_GoldenFlareBase {

    public abstract void action(String data) throws XPathExpressionException;
}

class CWE643_P12_V2_GoldenFlareSink extends CWE643_P12_V2_GoldenFlareBase {

    public void action(String data) throws XPathExpressionException {
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
}
