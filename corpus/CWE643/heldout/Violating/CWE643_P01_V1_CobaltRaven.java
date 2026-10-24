import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P01_V1_CobaltRaven {

    public void runCobaltRaven() throws XPathExpressionException {
        String data;
        data = System.getenv("COBALT_RAVEN_ADD");
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
