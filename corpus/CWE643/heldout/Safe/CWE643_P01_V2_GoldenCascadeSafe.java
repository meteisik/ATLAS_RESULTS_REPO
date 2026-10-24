import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P01_V2_GoldenCascadeSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void runGoldenCascade() throws XPathExpressionException {
        String data;
        if (IO.STATIC_FINAL_TRUE) {
            data = "foo";
        } else {
            data = null;
        }
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
}
