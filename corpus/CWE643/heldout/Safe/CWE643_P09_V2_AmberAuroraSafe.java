import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P09_V2_AmberAuroraSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    static class Container {
        public String containerOne;
    }

    public void runAmberAurora() throws XPathExpressionException {
        String data;
        if (IO.staticFive == 5) {
            data = "foo";
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE643_P09_V2_AmberAuroraSafeSink()).sinkAmberAurora(dataContainer);
    }
}

class CWE643_P09_V2_AmberAuroraSafeSink {

    public void sinkAmberAurora(CWE643_P09_V2_AmberAuroraSafe.Container dataContainer) throws XPathExpressionException {
        String data = dataContainer.containerOne;
        String amberAuroraXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            amberAuroraXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            amberAuroraXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] amberAuroraTokens = data.split("||");
            if (amberAuroraTokens.length < 2) {
                return;
            }
            String amberAuroraUser = amberAuroraTokens[0];
            String amberAuroraPass = amberAuroraTokens[1];
            XPath amberAuroraXPath = XPathFactory.newInstance().newXPath();
            InputSource amberAuroraXml = new InputSource(amberAuroraXmlFile);
            String amberAuroraQuery = "//users/user[name/text()='" + amberAuroraUser
                    + "' and pass/text()='" + amberAuroraPass + "']" + "/secret/text()";
            String amberAuroraSecret = (String) amberAuroraXPath.evaluate(amberAuroraQuery, amberAuroraXml, XPathConstants.STRING);
            System.out.println(amberAuroraSecret);
        }
    }
}
