import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P06_V1_JadeGlint {

    public void runJadeGlint() throws XPathExpressionException {
        String data;
        data = System.getenv("JADE_GLINT_ADD");
        (new CWE643_P06_V1_JadeGlintSink()).sinkJadeGlint(data);
    }
}

class CWE643_P06_V1_JadeGlintSink {

    public void sinkJadeGlint(String data) throws XPathExpressionException {
        String jadeGlintXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            jadeGlintXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            jadeGlintXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] jadeGlintTokens = data.split("||");
            if (jadeGlintTokens.length < 2) {
                return;
            }
            String jadeGlintUser = jadeGlintTokens[0];
            String jadeGlintPass = jadeGlintTokens[1];
            XPath jadeGlintXPath = XPathFactory.newInstance().newXPath();
            InputSource jadeGlintXml = new InputSource(jadeGlintXmlFile);
            String jadeGlintQuery = "//users/user[name/text()='" + jadeGlintUser
                    + "' and pass/text()='" + jadeGlintPass + "']" + "/secret/text()";
            String jadeGlintSecret = (String) jadeGlintXPath.evaluate(jadeGlintQuery, jadeGlintXml, XPathConstants.STRING);
            System.out.println(jadeGlintSecret);
        }
    }
}
