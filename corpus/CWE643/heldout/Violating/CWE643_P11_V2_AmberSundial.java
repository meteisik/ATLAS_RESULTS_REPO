import java.util.HashMap;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P11_V2_AmberSundial {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void runAmberSundial() throws XPathExpressionException {
        String data;
        if (IO.staticTrue) {
            data = System.getenv("AMBER_SUNDIAL_ADD");
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE643_P11_V2_AmberSundialSink()).sinkAmberSundial(dataHashMap);
    }
}

class CWE643_P11_V2_AmberSundialSink {

    public void sinkAmberSundial(HashMap<Integer, String> dataHashMap) throws XPathExpressionException {
        String data = dataHashMap.get(2);
        String amberSundialXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            amberSundialXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            amberSundialXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] amberSundialTokens = data.split("||");
            if (amberSundialTokens.length < 2) {
                return;
            }
            String amberSundialUser = amberSundialTokens[0];
            String amberSundialPass = amberSundialTokens[1];
            XPath amberSundialXPath = XPathFactory.newInstance().newXPath();
            InputSource amberSundialXml = new InputSource(amberSundialXmlFile);
            String amberSundialQuery = "//users/user[name/text()='" + amberSundialUser
                    + "' and pass/text()='" + amberSundialPass + "']" + "/secret/text()";
            String amberSundialSecret = (String) amberSundialXPath.evaluate(amberSundialQuery, amberSundialXml, XPathConstants.STRING);
            System.out.println(amberSundialSecret);
        }
    }
}
