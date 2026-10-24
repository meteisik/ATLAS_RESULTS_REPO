import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P12_V2_CobaltRavenSafe {
    private static int privateFive = 5;

    public void runCobaltRaven() throws XPathExpressionException {
        String data;
        if (privateFive == 5) {
            data = "foo";
        } else {
            data = null;
        }
        CWE643_P12_V2_CobaltRavenSafeBase baseObject = new CWE643_P12_V2_CobaltRavenSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE643_P12_V2_CobaltRavenSafeBase {

    public abstract void action(String data) throws XPathExpressionException;
}

class CWE643_P12_V2_CobaltRavenSafeSink extends CWE643_P12_V2_CobaltRavenSafeBase {

    public void action(String data) throws XPathExpressionException {
        String cobaltRavenXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            cobaltRavenXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            cobaltRavenXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] cobaltRavenTokens = data.split("||");
            if (cobaltRavenTokens.length < 2) {
                return;
            }
            String cobaltRavenUser = cobaltRavenTokens[0];
            String cobaltRavenPass = cobaltRavenTokens[1];
            XPath cobaltRavenXPath = XPathFactory.newInstance().newXPath();
            InputSource cobaltRavenXml = new InputSource(cobaltRavenXmlFile);
            String cobaltRavenQuery = "//users/user[name/text()='" + cobaltRavenUser
                    + "' and pass/text()='" + cobaltRavenPass + "']" + "/secret/text()";
            String cobaltRavenSecret = (String) cobaltRavenXPath.evaluate(cobaltRavenQuery, cobaltRavenXml, XPathConstants.STRING);
            System.out.println(cobaltRavenSecret);
        }
    }
}
