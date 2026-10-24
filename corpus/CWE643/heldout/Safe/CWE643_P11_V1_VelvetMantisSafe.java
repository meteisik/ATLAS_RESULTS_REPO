import java.util.HashMap;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P11_V1_VelvetMantisSafe {

    public void runVelvetMantis() throws XPathExpressionException {
        String data;
        data = "foo";
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE643_P11_V1_VelvetMantisSafeSink()).sinkVelvetMantis(dataHashMap);
    }
}

class CWE643_P11_V1_VelvetMantisSafeSink {

    public void sinkVelvetMantis(HashMap<Integer, String> dataHashMap) throws XPathExpressionException {
        String data = dataHashMap.get(2);
        String velvetMantisXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            velvetMantisXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            velvetMantisXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] velvetMantisTokens = data.split("||");
            if (velvetMantisTokens.length < 2) {
                return;
            }
            String velvetMantisUser = velvetMantisTokens[0];
            String velvetMantisPass = velvetMantisTokens[1];
            XPath velvetMantisXPath = XPathFactory.newInstance().newXPath();
            InputSource velvetMantisXml = new InputSource(velvetMantisXmlFile);
            String velvetMantisQuery = "//users/user[name/text()='" + velvetMantisUser
                    + "' and pass/text()='" + velvetMantisPass + "']" + "/secret/text()";
            String velvetMantisSecret = (String) velvetMantisXPath.evaluate(velvetMantisQuery, velvetMantisXml, XPathConstants.STRING);
            System.out.println(velvetMantisSecret);
        }
    }
}
