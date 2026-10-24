import java.util.HashMap;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P11_V2_AmberQuartz {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void runAmberQuartz() throws XPathExpressionException {
        String data;
        if (IO.STATIC_FINAL_TRUE) {
            data = System.getenv("AMBER_QUARTZ_ADD");
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE643_P11_V2_AmberQuartzSink()).sinkAmberQuartz(dataHashMap);
    }
}

class CWE643_P11_V2_AmberQuartzSink {

    public void sinkAmberQuartz(HashMap<Integer, String> dataHashMap) throws XPathExpressionException {
        String data = dataHashMap.get(2);
        String amberQuartzXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            amberQuartzXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            amberQuartzXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] amberQuartzTokens = data.split("||");
            if (amberQuartzTokens.length < 2) {
                return;
            }
            String amberQuartzUser = amberQuartzTokens[0];
            String amberQuartzPass = amberQuartzTokens[1];
            XPath amberQuartzXPath = XPathFactory.newInstance().newXPath();
            InputSource amberQuartzXml = new InputSource(amberQuartzXmlFile);
            String amberQuartzQuery = "//users/user[name/text()='" + amberQuartzUser
                    + "' and pass/text()='" + amberQuartzPass + "']" + "/secret/text()";
            String amberQuartzSecret = (String) amberQuartzXPath.evaluate(amberQuartzQuery, amberQuartzXml, XPathConstants.STRING);
            System.out.println(amberQuartzSecret);
        }
    }
}
