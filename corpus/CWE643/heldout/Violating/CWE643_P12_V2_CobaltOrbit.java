import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P12_V2_CobaltOrbit {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    public void runCobaltOrbit() throws XPathExpressionException {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = System.getenv("COBALT_ORBIT_ADD");
        } else {
            data = null;
        }
        CWE643_P12_V2_CobaltOrbitBase baseObject = new CWE643_P12_V2_CobaltOrbitSink();
        baseObject.action(data);
    }
}

abstract class CWE643_P12_V2_CobaltOrbitBase {

    public abstract void action(String data) throws XPathExpressionException;
}

class CWE643_P12_V2_CobaltOrbitSink extends CWE643_P12_V2_CobaltOrbitBase {

    public void action(String data) throws XPathExpressionException {
        String cobaltOrbitXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            cobaltOrbitXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            cobaltOrbitXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] cobaltOrbitTokens = data.split("||");
            if (cobaltOrbitTokens.length < 2) {
                return;
            }
            String cobaltOrbitUser = cobaltOrbitTokens[0];
            String cobaltOrbitPass = cobaltOrbitTokens[1];
            XPath cobaltOrbitXPath = XPathFactory.newInstance().newXPath();
            InputSource cobaltOrbitXml = new InputSource(cobaltOrbitXmlFile);
            String cobaltOrbitQuery = "//users/user[name/text()='" + cobaltOrbitUser
                    + "' and pass/text()='" + cobaltOrbitPass + "']" + "/secret/text()";
            String cobaltOrbitSecret = (String) cobaltOrbitXPath.evaluate(cobaltOrbitQuery, cobaltOrbitXml, XPathConstants.STRING);
            System.out.println(cobaltOrbitSecret);
        }
    }
}
