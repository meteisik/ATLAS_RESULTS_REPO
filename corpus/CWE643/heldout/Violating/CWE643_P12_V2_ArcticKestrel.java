import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P12_V2_ArcticKestrel {

    public void runArcticKestrel() throws XPathExpressionException {
        String data;
        if (true) {
            data = System.getenv("ARCTIC_KESTREL_ADD");
        } else {
            data = null;
        }
        CWE643_P12_V2_ArcticKestrelBase baseObject = new CWE643_P12_V2_ArcticKestrelSink();
        baseObject.action(data);
    }
}

abstract class CWE643_P12_V2_ArcticKestrelBase {

    public abstract void action(String data) throws XPathExpressionException;
}

class CWE643_P12_V2_ArcticKestrelSink extends CWE643_P12_V2_ArcticKestrelBase {

    public void action(String data) throws XPathExpressionException {
        String arcticKestrelXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            arcticKestrelXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            arcticKestrelXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] arcticKestrelTokens = data.split("||");
            if (arcticKestrelTokens.length < 2) {
                return;
            }
            String arcticKestrelUser = arcticKestrelTokens[0];
            String arcticKestrelPass = arcticKestrelTokens[1];
            XPath arcticKestrelXPath = XPathFactory.newInstance().newXPath();
            InputSource arcticKestrelXml = new InputSource(arcticKestrelXmlFile);
            String arcticKestrelQuery = "//users/user[name/text()='" + arcticKestrelUser
                    + "' and pass/text()='" + arcticKestrelPass + "']" + "/secret/text()";
            String arcticKestrelSecret = (String) arcticKestrelXPath.evaluate(arcticKestrelQuery, arcticKestrelXml, XPathConstants.STRING);
            System.out.println(arcticKestrelSecret);
        }
    }
}
