import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P05_V1_JadeGlintSafe {

    private String jadeGlintData;

    private void sinkJadeGlint() throws XPathExpressionException {
        String data = jadeGlintData;
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

    public void runJadeGlint() throws XPathExpressionException {
        String data;
        data = "foo";
        jadeGlintData = data;
        sinkJadeGlint();
    }
}
