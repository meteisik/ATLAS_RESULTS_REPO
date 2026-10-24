import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P08_V2_SilentLanternSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void runSilentLantern() throws XPathExpressionException {
        String data;
        if (IO.STATIC_FINAL_TRUE) {
            data = "foo";
        } else {
            data = null;
        }
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE643_P08_V2_SilentLanternSafeSink()).sinkSilentLantern(dataArray);
    }
}

class CWE643_P08_V2_SilentLanternSafeSink {

    public void sinkSilentLantern(String[] dataArray) throws XPathExpressionException {
        String data = dataArray[2];
        String silentLanternXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            silentLanternXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            silentLanternXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] silentLanternTokens = data.split("||");
            if (silentLanternTokens.length < 2) {
                return;
            }
            String silentLanternUser = silentLanternTokens[0];
            String silentLanternPass = silentLanternTokens[1];
            XPath silentLanternXPath = XPathFactory.newInstance().newXPath();
            InputSource silentLanternXml = new InputSource(silentLanternXmlFile);
            String silentLanternQuery = "//users/user[name/text()='" + silentLanternUser
                    + "' and pass/text()='" + silentLanternPass + "']" + "/secret/text()";
            String silentLanternSecret = (String) silentLanternXPath.evaluate(silentLanternQuery, silentLanternXml, XPathConstants.STRING);
            System.out.println(silentLanternSecret);
        }
    }
}
