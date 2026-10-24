import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P12_V2_ArcticLotus {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    public void runArcticLotus() throws XPathExpressionException {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = System.getenv("ARCTIC_LOTUS_ADD");
        } else {
            data = null;
        }
        CWE643_P12_V2_ArcticLotusBase baseObject = new CWE643_P12_V2_ArcticLotusSink();
        baseObject.action(data);
    }
}

abstract class CWE643_P12_V2_ArcticLotusBase {

    public abstract void action(String data) throws XPathExpressionException;
}

class CWE643_P12_V2_ArcticLotusSink extends CWE643_P12_V2_ArcticLotusBase {

    public void action(String data) throws XPathExpressionException {
        String arcticLotusXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            arcticLotusXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            arcticLotusXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] arcticLotusTokens = data.split("||");
            if (arcticLotusTokens.length < 2) {
                return;
            }
            String arcticLotusUser = arcticLotusTokens[0];
            String arcticLotusPass = arcticLotusTokens[1];
            XPath arcticLotusXPath = XPathFactory.newInstance().newXPath();
            InputSource arcticLotusXml = new InputSource(arcticLotusXmlFile);
            String arcticLotusQuery = "//users/user[name/text()='" + arcticLotusUser
                    + "' and pass/text()='" + arcticLotusPass + "']" + "/secret/text()";
            String arcticLotusSecret = (String) arcticLotusXPath.evaluate(arcticLotusQuery, arcticLotusXml, XPathConstants.STRING);
            System.out.println(arcticLotusSecret);
        }
    }
}
