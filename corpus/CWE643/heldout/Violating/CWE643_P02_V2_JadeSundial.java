import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P02_V2_JadeSundial {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void runJadeSundial() throws XPathExpressionException {
        String dataCopy;
        {
            String data;
            if (IO.STATIC_FINAL_TRUE) {
                data = System.getenv("JADE_SUNDIAL_ADD");
            } else {
                data = null;
            }
            dataCopy = data;
        }
        {
            String data = dataCopy;
            String jadeSundialXmlFile = null;
            if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
                jadeSundialXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
            } else {
                jadeSundialXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
            }
            if (data != null) {
                String[] jadeSundialTokens = data.split("||");
                if (jadeSundialTokens.length < 2) {
                    return;
                }
                String jadeSundialUser = jadeSundialTokens[0];
                String jadeSundialPass = jadeSundialTokens[1];
                XPath jadeSundialXPath = XPathFactory.newInstance().newXPath();
                InputSource jadeSundialXml = new InputSource(jadeSundialXmlFile);
                String jadeSundialQuery = "//users/user[name/text()='" + jadeSundialUser
                        + "' and pass/text()='" + jadeSundialPass + "']" + "/secret/text()";
                String jadeSundialSecret = (String) jadeSundialXPath.evaluate(jadeSundialQuery, jadeSundialXml, XPathConstants.STRING);
                System.out.println(jadeSundialSecret);
            }
        }
    }
}
