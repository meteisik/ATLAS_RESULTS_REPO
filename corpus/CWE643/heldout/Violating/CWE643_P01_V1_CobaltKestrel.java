import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P01_V1_CobaltKestrel {

    public void runCobaltKestrel() throws XPathExpressionException {
        String data;
        data = System.getenv("COBALT_KESTREL_ADD");
        String cobaltKestrelXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            cobaltKestrelXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            cobaltKestrelXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] cobaltKestrelTokens = data.split("||");
            if (cobaltKestrelTokens.length < 2) {
                return;
            }
            String cobaltKestrelUser = cobaltKestrelTokens[0];
            String cobaltKestrelPass = cobaltKestrelTokens[1];
            XPath cobaltKestrelXPath = XPathFactory.newInstance().newXPath();
            InputSource cobaltKestrelXml = new InputSource(cobaltKestrelXmlFile);
            String cobaltKestrelQuery = "//users/user[name/text()='" + cobaltKestrelUser
                    + "' and pass/text()='" + cobaltKestrelPass + "']" + "/secret/text()";
            String cobaltKestrelSecret = (String) cobaltKestrelXPath.evaluate(cobaltKestrelQuery, cobaltKestrelXml, XPathConstants.STRING);
            System.out.println(cobaltKestrelSecret);
        }
    }
}
