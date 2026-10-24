import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P05_V2_OnyxNebula {
    private static boolean privateReturnsTrue() { return true; }

    private String onyxNebulaData;

    private void sinkOnyxNebula() throws XPathExpressionException {
        String data = onyxNebulaData;
        String onyxNebulaXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            onyxNebulaXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            onyxNebulaXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] onyxNebulaTokens = data.split("||");
            if (onyxNebulaTokens.length < 2) {
                return;
            }
            String onyxNebulaUser = onyxNebulaTokens[0];
            String onyxNebulaPass = onyxNebulaTokens[1];
            XPath onyxNebulaXPath = XPathFactory.newInstance().newXPath();
            InputSource onyxNebulaXml = new InputSource(onyxNebulaXmlFile);
            String onyxNebulaQuery = "//users/user[name/text()='" + onyxNebulaUser
                    + "' and pass/text()='" + onyxNebulaPass + "']" + "/secret/text()";
            String onyxNebulaSecret = (String) onyxNebulaXPath.evaluate(onyxNebulaQuery, onyxNebulaXml, XPathConstants.STRING);
            System.out.println(onyxNebulaSecret);
        }
    }

    public void runOnyxNebula() throws XPathExpressionException {
        String data;
        if (privateReturnsTrue()) {
            data = System.getenv("ONYX_NEBULA_ADD");
        } else {
            data = null;
        }
        onyxNebulaData = data;
        sinkOnyxNebula();
    }
}
