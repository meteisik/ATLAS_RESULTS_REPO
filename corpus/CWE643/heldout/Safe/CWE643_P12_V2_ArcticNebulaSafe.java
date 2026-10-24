import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P12_V2_ArcticNebulaSafe {
    private static boolean privateTrue = true;

    public void runArcticNebula() throws XPathExpressionException {
        String data;
        if (privateTrue) {
            data = "foo";
        } else {
            data = null;
        }
        CWE643_P12_V2_ArcticNebulaSafeBase baseObject = new CWE643_P12_V2_ArcticNebulaSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE643_P12_V2_ArcticNebulaSafeBase {

    public abstract void action(String data) throws XPathExpressionException;
}

class CWE643_P12_V2_ArcticNebulaSafeSink extends CWE643_P12_V2_ArcticNebulaSafeBase {

    public void action(String data) throws XPathExpressionException {
        String arcticNebulaXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            arcticNebulaXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            arcticNebulaXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] arcticNebulaTokens = data.split("||");
            if (arcticNebulaTokens.length < 2) {
                return;
            }
            String arcticNebulaUser = arcticNebulaTokens[0];
            String arcticNebulaPass = arcticNebulaTokens[1];
            XPath arcticNebulaXPath = XPathFactory.newInstance().newXPath();
            InputSource arcticNebulaXml = new InputSource(arcticNebulaXmlFile);
            String arcticNebulaQuery = "//users/user[name/text()='" + arcticNebulaUser
                    + "' and pass/text()='" + arcticNebulaPass + "']" + "/secret/text()";
            String arcticNebulaSecret = (String) arcticNebulaXPath.evaluate(arcticNebulaQuery, arcticNebulaXml, XPathConstants.STRING);
            System.out.println(arcticNebulaSecret);
        }
    }
}
