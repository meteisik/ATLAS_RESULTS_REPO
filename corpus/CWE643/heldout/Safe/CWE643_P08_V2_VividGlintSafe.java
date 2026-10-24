import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P08_V2_VividGlintSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void runVividGlint() throws XPathExpressionException {
        String data;
        if (IO.STATIC_FINAL_FIVE == 5) {
            data = "foo";
        } else {
            data = null;
        }
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE643_P08_V2_VividGlintSafeSink()).sinkVividGlint(dataArray);
    }
}

class CWE643_P08_V2_VividGlintSafeSink {

    public void sinkVividGlint(String[] dataArray) throws XPathExpressionException {
        String data = dataArray[2];
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
