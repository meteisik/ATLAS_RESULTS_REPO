import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P08_V2_SilentLotusSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void runSilentLotus() throws XPathExpressionException {
        String data;
        if (IO.staticTrue) {
            data = "foo";
        } else {
            data = null;
        }
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE643_P08_V2_SilentLotusSafeSink()).sinkSilentLotus(dataArray);
    }
}

class CWE643_P08_V2_SilentLotusSafeSink {

    public void sinkSilentLotus(String[] dataArray) throws XPathExpressionException {
        String data = dataArray[2];
        String silentLotusXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            silentLotusXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            silentLotusXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] silentLotusTokens = data.split("||");
            if (silentLotusTokens.length < 2) {
                return;
            }
            String silentLotusUser = silentLotusTokens[0];
            String silentLotusPass = silentLotusTokens[1];
            XPath silentLotusXPath = XPathFactory.newInstance().newXPath();
            InputSource silentLotusXml = new InputSource(silentLotusXmlFile);
            String silentLotusQuery = "//users/user[name/text()='" + silentLotusUser
                    + "' and pass/text()='" + silentLotusPass + "']" + "/secret/text()";
            String silentLotusSecret = (String) silentLotusXPath.evaluate(silentLotusQuery, silentLotusXml, XPathConstants.STRING);
            System.out.println(silentLotusSecret);
        }
    }
}
