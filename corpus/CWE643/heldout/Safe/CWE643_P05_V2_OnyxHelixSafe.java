import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P05_V2_OnyxHelixSafe {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    private String onyxHelixData;

    private void sinkOnyxHelix() throws XPathExpressionException {
        String data = onyxHelixData;
        String onyxHelixXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            onyxHelixXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            onyxHelixXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] onyxHelixTokens = data.split("||");
            if (onyxHelixTokens.length < 2) {
                return;
            }
            String onyxHelixUser = onyxHelixTokens[0];
            String onyxHelixPass = onyxHelixTokens[1];
            XPath onyxHelixXPath = XPathFactory.newInstance().newXPath();
            InputSource onyxHelixXml = new InputSource(onyxHelixXmlFile);
            String onyxHelixQuery = "//users/user[name/text()='" + onyxHelixUser
                    + "' and pass/text()='" + onyxHelixPass + "']" + "/secret/text()";
            String onyxHelixSecret = (String) onyxHelixXPath.evaluate(onyxHelixQuery, onyxHelixXml, XPathConstants.STRING);
            System.out.println(onyxHelixSecret);
        }
    }

    public void runOnyxHelix() throws XPathExpressionException {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = "foo";
        } else {
            data = null;
        }
        onyxHelixData = data;
        sinkOnyxHelix();
    }
}
