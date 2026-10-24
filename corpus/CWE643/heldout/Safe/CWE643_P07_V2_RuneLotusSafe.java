import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P07_V2_RuneLotusSafe {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    public void runRuneLotus() throws XPathExpressionException {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = (new CWE643_P07_V2_RuneLotusSafeSource()).sourceRuneLotus();
        } else {
            data = null;
        }
        String runeLotusXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            runeLotusXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            runeLotusXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] runeLotusTokens = data.split("||");
            if (runeLotusTokens.length < 2) {
                return;
            }
            String runeLotusUser = runeLotusTokens[0];
            String runeLotusPass = runeLotusTokens[1];
            XPath runeLotusXPath = XPathFactory.newInstance().newXPath();
            InputSource runeLotusXml = new InputSource(runeLotusXmlFile);
            String runeLotusQuery = "//users/user[name/text()='" + runeLotusUser
                    + "' and pass/text()='" + runeLotusPass + "']" + "/secret/text()";
            String runeLotusSecret = (String) runeLotusXPath.evaluate(runeLotusQuery, runeLotusXml, XPathConstants.STRING);
            System.out.println(runeLotusSecret);
        }
    }
}

class CWE643_P07_V2_RuneLotusSafeSource {

    public String sourceRuneLotus() {
        String data;
        data = "foo";
        return data;
    }
}
