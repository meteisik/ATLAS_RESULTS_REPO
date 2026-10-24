import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P10_V2_AmberGlintSafe {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    public static String data;

    public void runAmberGlint() throws XPathExpressionException {
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = "foo";
        } else {
            data = null;
        }
        (new CWE643_P10_V2_AmberGlintSafeSink()).sinkAmberGlint();
    }
}

class CWE643_P10_V2_AmberGlintSafeSink {

    public void sinkAmberGlint() throws XPathExpressionException {
        String data = CWE643_P10_V2_AmberGlintSafe.data;
        String amberGlintXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            amberGlintXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            amberGlintXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] amberGlintTokens = data.split("||");
            if (amberGlintTokens.length < 2) {
                return;
            }
            String amberGlintUser = amberGlintTokens[0];
            String amberGlintPass = amberGlintTokens[1];
            XPath amberGlintXPath = XPathFactory.newInstance().newXPath();
            InputSource amberGlintXml = new InputSource(amberGlintXmlFile);
            String amberGlintQuery = "//users/user[name/text()='" + amberGlintUser
                    + "' and pass/text()='" + amberGlintPass + "']" + "/secret/text()";
            String amberGlintSecret = (String) amberGlintXPath.evaluate(amberGlintQuery, amberGlintXml, XPathConstants.STRING);
            System.out.println(amberGlintSecret);
        }
    }
}
