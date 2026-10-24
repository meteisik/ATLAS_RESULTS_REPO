import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P12_V1_AmberQuartzSafe {

    public void runAmberQuartz() throws XPathExpressionException {
        String data;
        data = "foo";
        CWE643_P12_V1_AmberQuartzSafeBase baseObject = new CWE643_P12_V1_AmberQuartzSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE643_P12_V1_AmberQuartzSafeBase {

    public abstract void action(String data) throws XPathExpressionException;
}

class CWE643_P12_V1_AmberQuartzSafeSink extends CWE643_P12_V1_AmberQuartzSafeBase {

    public void action(String data) throws XPathExpressionException {
        String amberQuartzXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            amberQuartzXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            amberQuartzXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] amberQuartzTokens = data.split("||");
            if (amberQuartzTokens.length < 2) {
                return;
            }
            String amberQuartzUser = amberQuartzTokens[0];
            String amberQuartzPass = amberQuartzTokens[1];
            XPath amberQuartzXPath = XPathFactory.newInstance().newXPath();
            InputSource amberQuartzXml = new InputSource(amberQuartzXmlFile);
            String amberQuartzQuery = "//users/user[name/text()='" + amberQuartzUser
                    + "' and pass/text()='" + amberQuartzPass + "']" + "/secret/text()";
            String amberQuartzSecret = (String) amberQuartzXPath.evaluate(amberQuartzQuery, amberQuartzXml, XPathConstants.STRING);
            System.out.println(amberQuartzSecret);
        }
    }
}
