import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P12_V1_VividSundialSafe {

    public void runVividSundial() throws XPathExpressionException {
        String data;
        data = "foo";
        CWE643_P12_V1_VividSundialSafeBase baseObject = new CWE643_P12_V1_VividSundialSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE643_P12_V1_VividSundialSafeBase {

    public abstract void action(String data) throws XPathExpressionException;
}

class CWE643_P12_V1_VividSundialSafeSink extends CWE643_P12_V1_VividSundialSafeBase {

    public void action(String data) throws XPathExpressionException {
        String vividSundialXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            vividSundialXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            vividSundialXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] vividSundialTokens = data.split("||");
            if (vividSundialTokens.length < 2) {
                return;
            }
            String vividSundialUser = vividSundialTokens[0];
            String vividSundialPass = vividSundialTokens[1];
            XPath vividSundialXPath = XPathFactory.newInstance().newXPath();
            InputSource vividSundialXml = new InputSource(vividSundialXmlFile);
            String vividSundialQuery = "//users/user[name/text()='" + vividSundialUser
                    + "' and pass/text()='" + vividSundialPass + "']" + "/secret/text()";
            String vividSundialSecret = (String) vividSundialXPath.evaluate(vividSundialQuery, vividSundialXml, XPathConstants.STRING);
            System.out.println(vividSundialSecret);
        }
    }
}
