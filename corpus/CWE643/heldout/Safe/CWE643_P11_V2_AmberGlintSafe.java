import java.util.HashMap;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P11_V2_AmberGlintSafe {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    public void runAmberGlint() throws XPathExpressionException {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = "foo";
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE643_P11_V2_AmberGlintSafeSink()).sinkAmberGlint(dataHashMap);
    }
}

class CWE643_P11_V2_AmberGlintSafeSink {

    public void sinkAmberGlint(HashMap<Integer, String> dataHashMap) throws XPathExpressionException {
        String data = dataHashMap.get(2);
        String amberGlintXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            amberGlintXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            amberGlintXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] amberGlintTokens = data.split("||");
            if (amberGlintTokens.length < 2) {
                return;
            }
            String amberGlintUser = amberGlintTokens[0];
            String amberGlintPass = amberGlintTokens[1];
            XPath amberGlintXPath = XPathFactory.newInstance().newXPath();
            InputSource amberGlintXml = new InputSource(amberGlintXmlFile);
            String amberGlintQuery = "//users/user[name/text()='" + amberGlintUser
                    + "' and pass/text()='" + amberGlintPass + "']" + "/secret/text()";
            String amberGlintSecret = (String) amberGlintXPath.evaluate(amberGlintQuery, amberGlintXml, XPathConstants.STRING);
            System.out.println(amberGlintSecret);
        }
    }
}
