import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P03_V2_JadeSignalSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    private void sinkJadeSignal(String data) throws XPathExpressionException {
        String jadeSignalXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            jadeSignalXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            jadeSignalXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] jadeSignalTokens = data.split("||");
            if (jadeSignalTokens.length < 2) {
                return;
            }
            String jadeSignalUser = jadeSignalTokens[0];
            String jadeSignalPass = jadeSignalTokens[1];
            XPath jadeSignalXPath = XPathFactory.newInstance().newXPath();
            InputSource jadeSignalXml = new InputSource(jadeSignalXmlFile);
            String jadeSignalQuery = "//users/user[name/text()='" + jadeSignalUser
                    + "' and pass/text()='" + jadeSignalPass + "']" + "/secret/text()";
            String jadeSignalSecret = (String) jadeSignalXPath.evaluate(jadeSignalQuery, jadeSignalXml, XPathConstants.STRING);
            System.out.println(jadeSignalSecret);
        }
    }

    public void runJadeSignal() throws XPathExpressionException {
        String data;
        if (IO.staticTrue) {
            data = "foo";
        } else {
            data = null;
        }
        sinkJadeSignal(data);
    }
}
