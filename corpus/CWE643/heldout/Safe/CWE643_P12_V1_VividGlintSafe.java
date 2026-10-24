import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P12_V1_VividGlintSafe {

    public void runVividGlint() throws XPathExpressionException {
        String data;
        data = "foo";
        CWE643_P12_V1_VividGlintSafeBase baseObject = new CWE643_P12_V1_VividGlintSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE643_P12_V1_VividGlintSafeBase {

    public abstract void action(String data) throws XPathExpressionException;
}

class CWE643_P12_V1_VividGlintSafeSink extends CWE643_P12_V1_VividGlintSafeBase {

    public void action(String data) throws XPathExpressionException {
        String vividGlintXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            vividGlintXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            vividGlintXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] vividGlintTokens = data.split("||");
            if (vividGlintTokens.length < 2) {
                return;
            }
            String vividGlintUser = vividGlintTokens[0];
            String vividGlintPass = vividGlintTokens[1];
            XPath vividGlintXPath = XPathFactory.newInstance().newXPath();
            InputSource vividGlintXml = new InputSource(vividGlintXmlFile);
            String vividGlintQuery = "//users/user[name/text()='" + vividGlintUser
                    + "' and pass/text()='" + vividGlintPass + "']" + "/secret/text()";
            String vividGlintSecret = (String) vividGlintXPath.evaluate(vividGlintQuery, vividGlintXml, XPathConstants.STRING);
            System.out.println(vividGlintSecret);
        }
    }
}
