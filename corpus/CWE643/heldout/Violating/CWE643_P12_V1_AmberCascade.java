import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P12_V1_AmberCascade {

    public void runAmberCascade() throws XPathExpressionException {
        String data;
        data = System.getenv("AMBER_CASCADE_ADD");
        CWE643_P12_V1_AmberCascadeBase baseObject = new CWE643_P12_V1_AmberCascadeSink();
        baseObject.action(data);
    }
}

abstract class CWE643_P12_V1_AmberCascadeBase {

    public abstract void action(String data) throws XPathExpressionException;
}

class CWE643_P12_V1_AmberCascadeSink extends CWE643_P12_V1_AmberCascadeBase {

    public void action(String data) throws XPathExpressionException {
        String amberCascadeXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            amberCascadeXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            amberCascadeXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] amberCascadeTokens = data.split("||");
            if (amberCascadeTokens.length < 2) {
                return;
            }
            String amberCascadeUser = amberCascadeTokens[0];
            String amberCascadePass = amberCascadeTokens[1];
            XPath amberCascadeXPath = XPathFactory.newInstance().newXPath();
            InputSource amberCascadeXml = new InputSource(amberCascadeXmlFile);
            String amberCascadeQuery = "//users/user[name/text()='" + amberCascadeUser
                    + "' and pass/text()='" + amberCascadePass + "']" + "/secret/text()";
            String amberCascadeSecret = (String) amberCascadeXPath.evaluate(amberCascadeQuery, amberCascadeXml, XPathConstants.STRING);
            System.out.println(amberCascadeSecret);
        }
    }
}
