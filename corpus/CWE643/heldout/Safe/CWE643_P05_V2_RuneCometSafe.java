import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P05_V2_RuneCometSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    private String runeCometData;

    private void sinkRuneComet() throws XPathExpressionException {
        String data = runeCometData;
        String runeCometXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            runeCometXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            runeCometXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] runeCometTokens = data.split("||");
            if (runeCometTokens.length < 2) {
                return;
            }
            String runeCometUser = runeCometTokens[0];
            String runeCometPass = runeCometTokens[1];
            XPath runeCometXPath = XPathFactory.newInstance().newXPath();
            InputSource runeCometXml = new InputSource(runeCometXmlFile);
            String runeCometQuery = "//users/user[name/text()='" + runeCometUser
                    + "' and pass/text()='" + runeCometPass + "']" + "/secret/text()";
            String runeCometSecret = (String) runeCometXPath.evaluate(runeCometQuery, runeCometXml, XPathConstants.STRING);
            System.out.println(runeCometSecret);
        }
    }

    public void runRuneComet() throws XPathExpressionException {
        String data;
        if (IO.STATIC_FINAL_FIVE == 5) {
            data = "foo";
        } else {
            data = null;
        }
        runeCometData = data;
        sinkRuneComet();
    }
}
