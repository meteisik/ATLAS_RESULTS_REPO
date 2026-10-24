import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P12_V1_AmberFlareSafe {

    public void runAmberFlare() throws XPathExpressionException {
        String data;
        data = "foo";
        CWE643_P12_V1_AmberFlareSafeBase baseObject = new CWE643_P12_V1_AmberFlareSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE643_P12_V1_AmberFlareSafeBase {

    public abstract void action(String data) throws XPathExpressionException;
}

class CWE643_P12_V1_AmberFlareSafeSink extends CWE643_P12_V1_AmberFlareSafeBase {

    public void action(String data) throws XPathExpressionException {
        String amberFlareXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            amberFlareXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            amberFlareXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] amberFlareTokens = data.split("||");
            if (amberFlareTokens.length < 2) {
                return;
            }
            String amberFlareUser = amberFlareTokens[0];
            String amberFlarePass = amberFlareTokens[1];
            XPath amberFlareXPath = XPathFactory.newInstance().newXPath();
            InputSource amberFlareXml = new InputSource(amberFlareXmlFile);
            String amberFlareQuery = "//users/user[name/text()='" + amberFlareUser
                    + "' and pass/text()='" + amberFlarePass + "']" + "/secret/text()";
            String amberFlareSecret = (String) amberFlareXPath.evaluate(amberFlareQuery, amberFlareXml, XPathConstants.STRING);
            System.out.println(amberFlareSecret);
        }
    }
}
