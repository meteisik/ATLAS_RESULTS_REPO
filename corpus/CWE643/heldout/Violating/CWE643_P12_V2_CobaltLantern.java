import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P12_V2_CobaltLantern {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    public void runCobaltLantern() throws XPathExpressionException {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = System.getenv("COBALT_LANTERN_ADD");
        } else {
            data = null;
        }
        CWE643_P12_V2_CobaltLanternBase baseObject = new CWE643_P12_V2_CobaltLanternSink();
        baseObject.action(data);
    }
}

abstract class CWE643_P12_V2_CobaltLanternBase {

    public abstract void action(String data) throws XPathExpressionException;
}

class CWE643_P12_V2_CobaltLanternSink extends CWE643_P12_V2_CobaltLanternBase {

    public void action(String data) throws XPathExpressionException {
        String cobaltLanternXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            cobaltLanternXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            cobaltLanternXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] cobaltLanternTokens = data.split("||");
            if (cobaltLanternTokens.length < 2) {
                return;
            }
            String cobaltLanternUser = cobaltLanternTokens[0];
            String cobaltLanternPass = cobaltLanternTokens[1];
            XPath cobaltLanternXPath = XPathFactory.newInstance().newXPath();
            InputSource cobaltLanternXml = new InputSource(cobaltLanternXmlFile);
            String cobaltLanternQuery = "//users/user[name/text()='" + cobaltLanternUser
                    + "' and pass/text()='" + cobaltLanternPass + "']" + "/secret/text()";
            String cobaltLanternSecret = (String) cobaltLanternXPath.evaluate(cobaltLanternQuery, cobaltLanternXml, XPathConstants.STRING);
            System.out.println(cobaltLanternSecret);
        }
    }
}
