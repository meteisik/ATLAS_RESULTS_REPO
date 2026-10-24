import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P08_V2_VelvetSundialSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void runVelvetSundial() throws XPathExpressionException {
        String data;
        if (IO.staticTrue) {
            data = "foo";
        } else {
            data = null;
        }
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE643_P08_V2_VelvetSundialSafeSink()).sinkVelvetSundial(dataArray);
    }
}

class CWE643_P08_V2_VelvetSundialSafeSink {

    public void sinkVelvetSundial(String[] dataArray) throws XPathExpressionException {
        String data = dataArray[2];
        String velvetSundialXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            velvetSundialXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            velvetSundialXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] velvetSundialTokens = data.split("||");
            if (velvetSundialTokens.length < 2) {
                return;
            }
            String velvetSundialUser = velvetSundialTokens[0];
            String velvetSundialPass = velvetSundialTokens[1];
            XPath velvetSundialXPath = XPathFactory.newInstance().newXPath();
            InputSource velvetSundialXml = new InputSource(velvetSundialXmlFile);
            String velvetSundialQuery = "//users/user[name/text()='" + velvetSundialUser
                    + "' and pass/text()='" + velvetSundialPass + "']" + "/secret/text()";
            String velvetSundialSecret = (String) velvetSundialXPath.evaluate(velvetSundialQuery, velvetSundialXml, XPathConstants.STRING);
            System.out.println(velvetSundialSecret);
        }
    }
}
