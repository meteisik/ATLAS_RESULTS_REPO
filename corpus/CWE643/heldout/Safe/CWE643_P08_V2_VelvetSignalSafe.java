import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P08_V2_VelvetSignalSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void runVelvetSignal() throws XPathExpressionException {
        String data;
        if (IO.STATIC_FINAL_TRUE) {
            data = "foo";
        } else {
            data = null;
        }
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE643_P08_V2_VelvetSignalSafeSink()).sinkVelvetSignal(dataArray);
    }
}

class CWE643_P08_V2_VelvetSignalSafeSink {

    public void sinkVelvetSignal(String[] dataArray) throws XPathExpressionException {
        String data = dataArray[2];
        String velvetSignalXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            velvetSignalXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            velvetSignalXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] velvetSignalTokens = data.split("||");
            if (velvetSignalTokens.length < 2) {
                return;
            }
            String velvetSignalUser = velvetSignalTokens[0];
            String velvetSignalPass = velvetSignalTokens[1];
            XPath velvetSignalXPath = XPathFactory.newInstance().newXPath();
            InputSource velvetSignalXml = new InputSource(velvetSignalXmlFile);
            String velvetSignalQuery = "//users/user[name/text()='" + velvetSignalUser
                    + "' and pass/text()='" + velvetSignalPass + "']" + "/secret/text()";
            String velvetSignalSecret = (String) velvetSignalXPath.evaluate(velvetSignalQuery, velvetSignalXml, XPathConstants.STRING);
            System.out.println(velvetSignalSecret);
        }
    }
}
