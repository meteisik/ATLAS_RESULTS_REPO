import java.util.HashMap;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P11_V1_VelvetSundialSafe {

    public void runVelvetSundial() throws XPathExpressionException {
        String data;
        data = "foo";
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE643_P11_V1_VelvetSundialSafeSink()).sinkVelvetSundial(dataHashMap);
    }
}

class CWE643_P11_V1_VelvetSundialSafeSink {

    public void sinkVelvetSundial(HashMap<Integer, String> dataHashMap) throws XPathExpressionException {
        String data = dataHashMap.get(2);
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
