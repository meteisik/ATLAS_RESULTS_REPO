import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P06_V1_NovaGlintSafe {

    public void runNovaGlint() throws XPathExpressionException {
        String data;
        data = "foo";
        (new CWE643_P06_V1_NovaGlintSafeSink()).sinkNovaGlint(data);
    }
}

class CWE643_P06_V1_NovaGlintSafeSink {

    public void sinkNovaGlint(String data) throws XPathExpressionException {
        String novaGlintXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            novaGlintXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            novaGlintXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] novaGlintTokens = data.split("||");
            if (novaGlintTokens.length < 2) {
                return;
            }
            String novaGlintUser = novaGlintTokens[0];
            String novaGlintPass = novaGlintTokens[1];
            XPath novaGlintXPath = XPathFactory.newInstance().newXPath();
            InputSource novaGlintXml = new InputSource(novaGlintXmlFile);
            String novaGlintQuery = "//users/user[name/text()='" + novaGlintUser
                    + "' and pass/text()='" + novaGlintPass + "']" + "/secret/text()";
            String novaGlintSecret = (String) novaGlintXPath.evaluate(novaGlintQuery, novaGlintXml, XPathConstants.STRING);
            System.out.println(novaGlintSecret);
        }
    }
}
