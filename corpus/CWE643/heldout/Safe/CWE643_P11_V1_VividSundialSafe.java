import java.util.HashMap;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P11_V1_VividSundialSafe {

    public void runVividSundial() throws XPathExpressionException {
        String data;
        data = "foo";
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE643_P11_V1_VividSundialSafeSink()).sinkVividSundial(dataHashMap);
    }
}

class CWE643_P11_V1_VividSundialSafeSink {

    public void sinkVividSundial(HashMap<Integer, String> dataHashMap) throws XPathExpressionException {
        String data = dataHashMap.get(2);
        String vividSundialXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            vividSundialXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            vividSundialXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] vividSundialTokens = data.split("||");
            if (vividSundialTokens.length < 2) {
                return;
            }
            String vividSundialUser = vividSundialTokens[0];
            String vividSundialPass = vividSundialTokens[1];
            XPath vividSundialXPath = XPathFactory.newInstance().newXPath();
            InputSource vividSundialXml = new InputSource(vividSundialXmlFile);
            String vividSundialQuery = "//users/user[name/text()='" + vividSundialUser
                    + "' and pass/text()='" + vividSundialPass + "']" + "/secret/text()";
            String vividSundialSecret = (String) vividSundialXPath.evaluate(vividSundialQuery, vividSundialXml, XPathConstants.STRING);
            System.out.println(vividSundialSecret);
        }
    }
}
