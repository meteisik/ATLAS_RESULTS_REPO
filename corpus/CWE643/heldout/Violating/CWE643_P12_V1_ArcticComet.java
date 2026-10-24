import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P12_V1_ArcticComet {

    public void runArcticComet() throws XPathExpressionException {
        String data;
        data = System.getenv("ARCTIC_COMET_ADD");
        CWE643_P12_V1_ArcticCometBase baseObject = new CWE643_P12_V1_ArcticCometSink();
        baseObject.action(data);
    }
}

abstract class CWE643_P12_V1_ArcticCometBase {

    public abstract void action(String data) throws XPathExpressionException;
}

class CWE643_P12_V1_ArcticCometSink extends CWE643_P12_V1_ArcticCometBase {

    public void action(String data) throws XPathExpressionException {
        String arcticCometXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            arcticCometXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            arcticCometXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] arcticCometTokens = data.split("||");
            if (arcticCometTokens.length < 2) {
                return;
            }
            String arcticCometUser = arcticCometTokens[0];
            String arcticCometPass = arcticCometTokens[1];
            XPath arcticCometXPath = XPathFactory.newInstance().newXPath();
            InputSource arcticCometXml = new InputSource(arcticCometXmlFile);
            String arcticCometQuery = "//users/user[name/text()='" + arcticCometUser
                    + "' and pass/text()='" + arcticCometPass + "']" + "/secret/text()";
            String arcticCometSecret = (String) arcticCometXPath.evaluate(arcticCometQuery, arcticCometXml, XPathConstants.STRING);
            System.out.println(arcticCometSecret);
        }
    }
}
