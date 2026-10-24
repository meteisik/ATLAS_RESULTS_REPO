import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P12_V2_GoldenMantisSafe {
    private static boolean privateReturnsTrue() { return true; }

    public void runGoldenMantis() throws XPathExpressionException {
        String data;
        if (privateReturnsTrue()) {
            data = "foo";
        } else {
            data = null;
        }
        CWE643_P12_V2_GoldenMantisSafeBase baseObject = new CWE643_P12_V2_GoldenMantisSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE643_P12_V2_GoldenMantisSafeBase {

    public abstract void action(String data) throws XPathExpressionException;
}

class CWE643_P12_V2_GoldenMantisSafeSink extends CWE643_P12_V2_GoldenMantisSafeBase {

    public void action(String data) throws XPathExpressionException {
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
}
