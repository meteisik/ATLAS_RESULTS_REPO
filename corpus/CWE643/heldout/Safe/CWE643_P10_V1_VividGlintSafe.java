import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P10_V1_VividGlintSafe {

    public static String data;

    public void runVividGlint() throws XPathExpressionException {
        data = "foo";
        (new CWE643_P10_V1_VividGlintSafeSink()).sinkVividGlint();
    }
}

class CWE643_P10_V1_VividGlintSafeSink {

    public void sinkVividGlint() throws XPathExpressionException {
        String data = CWE643_P10_V1_VividGlintSafe.data;
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
