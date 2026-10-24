import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P03_V2_NovaGlint {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    private void sinkNovaGlint(String data) throws XPathExpressionException {
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

    public void runNovaGlint() throws XPathExpressionException {
        String data;
        if (IO.STATIC_FINAL_FIVE == 5) {
            data = System.getenv("NOVA_GLINT_ADD");
        } else {
            data = null;
        }
        sinkNovaGlint(data);
    }
}
