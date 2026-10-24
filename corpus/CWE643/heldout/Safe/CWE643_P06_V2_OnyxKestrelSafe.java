import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P06_V2_OnyxKestrelSafe {
    private static int privateFive = 5;

    public void runOnyxKestrel() throws XPathExpressionException {
        String data;
        if (privateFive == 5) {
            data = "foo";
        } else {
            data = null;
        }
        (new CWE643_P06_V2_OnyxKestrelSafeSink()).sinkOnyxKestrel(data);
    }
}

class CWE643_P06_V2_OnyxKestrelSafeSink {

    public void sinkOnyxKestrel(String data) throws XPathExpressionException {
        String onyxKestrelXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            onyxKestrelXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            onyxKestrelXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] onyxKestrelTokens = data.split("||");
            if (onyxKestrelTokens.length < 2) {
                return;
            }
            String onyxKestrelUser = onyxKestrelTokens[0];
            String onyxKestrelPass = onyxKestrelTokens[1];
            XPath onyxKestrelXPath = XPathFactory.newInstance().newXPath();
            InputSource onyxKestrelXml = new InputSource(onyxKestrelXmlFile);
            String onyxKestrelQuery = "//users/user[name/text()='" + onyxKestrelUser
                    + "' and pass/text()='" + onyxKestrelPass + "']" + "/secret/text()";
            String onyxKestrelSecret = (String) onyxKestrelXPath.evaluate(onyxKestrelQuery, onyxKestrelXml, XPathConstants.STRING);
            System.out.println(onyxKestrelSecret);
        }
    }
}
