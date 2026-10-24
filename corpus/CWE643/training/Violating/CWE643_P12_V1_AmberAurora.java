import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P12_V1_AmberAurora {

    public void runAmberAurora() throws XPathExpressionException {
        String data;
        data = System.getenv("AMBER_AURORA_ADD");
        CWE643_P12_V1_AmberAuroraBase baseObject = new CWE643_P12_V1_AmberAuroraSink();
        baseObject.action(data);
    }
}

abstract class CWE643_P12_V1_AmberAuroraBase {

    public abstract void action(String data) throws XPathExpressionException;
}

class CWE643_P12_V1_AmberAuroraSink extends CWE643_P12_V1_AmberAuroraBase {

    public void action(String data) throws XPathExpressionException {
        String amberAuroraXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            amberAuroraXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            amberAuroraXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] amberAuroraTokens = data.split("||");
            if (amberAuroraTokens.length < 2) {
                return;
            }
            String amberAuroraUser = amberAuroraTokens[0];
            String amberAuroraPass = amberAuroraTokens[1];
            XPath amberAuroraXPath = XPathFactory.newInstance().newXPath();
            InputSource amberAuroraXml = new InputSource(amberAuroraXmlFile);
            String amberAuroraQuery = "//users/user[name/text()='" + amberAuroraUser
                    + "' and pass/text()='" + amberAuroraPass + "']" + "/secret/text()";
            String amberAuroraSecret = (String) amberAuroraXPath.evaluate(amberAuroraQuery, amberAuroraXml, XPathConstants.STRING);
            System.out.println(amberAuroraSecret);
        }
    }
}
