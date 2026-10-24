import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P03_V2_NovaAuroraSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    private void sinkNovaAurora(String data) throws XPathExpressionException {
        String novaAuroraXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            novaAuroraXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            novaAuroraXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] novaAuroraTokens = data.split("||");
            if (novaAuroraTokens.length < 2) {
                return;
            }
            String novaAuroraUser = novaAuroraTokens[0];
            String novaAuroraPass = novaAuroraTokens[1];
            XPath novaAuroraXPath = XPathFactory.newInstance().newXPath();
            InputSource novaAuroraXml = new InputSource(novaAuroraXmlFile);
            String novaAuroraQuery = "//users/user[name/text()='" + novaAuroraUser
                    + "' and pass/text()='" + novaAuroraPass + "']" + "/secret/text()";
            String novaAuroraSecret = (String) novaAuroraXPath.evaluate(novaAuroraQuery, novaAuroraXml, XPathConstants.STRING);
            System.out.println(novaAuroraSecret);
        }
    }

    public void runNovaAurora() throws XPathExpressionException {
        String data;
        if (IO.staticTrue) {
            data = "foo";
        } else {
            data = null;
        }
        sinkNovaAurora(data);
    }
}
