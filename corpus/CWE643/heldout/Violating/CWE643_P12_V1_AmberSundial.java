import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P12_V1_AmberSundial {

    public void runAmberSundial() throws XPathExpressionException {
        String data;
        data = System.getenv("AMBER_SUNDIAL_ADD");
        CWE643_P12_V1_AmberSundialBase baseObject = new CWE643_P12_V1_AmberSundialSink();
        baseObject.action(data);
    }
}

abstract class CWE643_P12_V1_AmberSundialBase {

    public abstract void action(String data) throws XPathExpressionException;
}

class CWE643_P12_V1_AmberSundialSink extends CWE643_P12_V1_AmberSundialBase {

    public void action(String data) throws XPathExpressionException {
        String amberSundialXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            amberSundialXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            amberSundialXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] amberSundialTokens = data.split("||");
            if (amberSundialTokens.length < 2) {
                return;
            }
            String amberSundialUser = amberSundialTokens[0];
            String amberSundialPass = amberSundialTokens[1];
            XPath amberSundialXPath = XPathFactory.newInstance().newXPath();
            InputSource amberSundialXml = new InputSource(amberSundialXmlFile);
            String amberSundialQuery = "//users/user[name/text()='" + amberSundialUser
                    + "' and pass/text()='" + amberSundialPass + "']" + "/secret/text()";
            String amberSundialSecret = (String) amberSundialXPath.evaluate(amberSundialQuery, amberSundialXml, XPathConstants.STRING);
            System.out.println(amberSundialSecret);
        }
    }
}
