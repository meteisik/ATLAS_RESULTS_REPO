import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P03_V2_JadeQuartz {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    private void sinkJadeQuartz(String data) throws XPathExpressionException {
        String jadeQuartzXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            jadeQuartzXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            jadeQuartzXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] jadeQuartzTokens = data.split("||");
            if (jadeQuartzTokens.length < 2) {
                return;
            }
            String jadeQuartzUser = jadeQuartzTokens[0];
            String jadeQuartzPass = jadeQuartzTokens[1];
            XPath jadeQuartzXPath = XPathFactory.newInstance().newXPath();
            InputSource jadeQuartzXml = new InputSource(jadeQuartzXmlFile);
            String jadeQuartzQuery = "//users/user[name/text()='" + jadeQuartzUser
                    + "' and pass/text()='" + jadeQuartzPass + "']" + "/secret/text()";
            String jadeQuartzSecret = (String) jadeQuartzXPath.evaluate(jadeQuartzQuery, jadeQuartzXml, XPathConstants.STRING);
            System.out.println(jadeQuartzSecret);
        }
    }

    public void runJadeQuartz() throws XPathExpressionException {
        String data;
        if (IO.STATIC_FINAL_TRUE) {
            data = System.getenv("JADE_QUARTZ_ADD");
        } else {
            data = null;
        }
        sinkJadeQuartz(data);
    }
}
