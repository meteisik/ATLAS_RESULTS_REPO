import java.util.HashMap;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P11_V2_AmberMantisSafe {
    private static int privateFive = 5;

    public void runAmberMantis() throws XPathExpressionException {
        String data;
        if (privateFive == 5) {
            data = "foo";
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE643_P11_V2_AmberMantisSafeSink()).sinkAmberMantis(dataHashMap);
    }
}

class CWE643_P11_V2_AmberMantisSafeSink {

    public void sinkAmberMantis(HashMap<Integer, String> dataHashMap) throws XPathExpressionException {
        String data = dataHashMap.get(2);
        String amberMantisXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            amberMantisXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            amberMantisXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] amberMantisTokens = data.split("||");
            if (amberMantisTokens.length < 2) {
                return;
            }
            String amberMantisUser = amberMantisTokens[0];
            String amberMantisPass = amberMantisTokens[1];
            XPath amberMantisXPath = XPathFactory.newInstance().newXPath();
            InputSource amberMantisXml = new InputSource(amberMantisXmlFile);
            String amberMantisQuery = "//users/user[name/text()='" + amberMantisUser
                    + "' and pass/text()='" + amberMantisPass + "']" + "/secret/text()";
            String amberMantisSecret = (String) amberMantisXPath.evaluate(amberMantisQuery, amberMantisXml, XPathConstants.STRING);
            System.out.println(amberMantisSecret);
        }
    }
}
