import java.util.HashMap;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P11_V1_VelvetCascadeSafe {

    public void runVelvetCascade() throws XPathExpressionException {
        String data;
        data = "foo";
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE643_P11_V1_VelvetCascadeSafeSink()).sinkVelvetCascade(dataHashMap);
    }
}

class CWE643_P11_V1_VelvetCascadeSafeSink {

    public void sinkVelvetCascade(HashMap<Integer, String> dataHashMap) throws XPathExpressionException {
        String data = dataHashMap.get(2);
        String velvetCascadeXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            velvetCascadeXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            velvetCascadeXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] velvetCascadeTokens = data.split("||");
            if (velvetCascadeTokens.length < 2) {
                return;
            }
            String velvetCascadeUser = velvetCascadeTokens[0];
            String velvetCascadePass = velvetCascadeTokens[1];
            XPath velvetCascadeXPath = XPathFactory.newInstance().newXPath();
            InputSource velvetCascadeXml = new InputSource(velvetCascadeXmlFile);
            String velvetCascadeQuery = "//users/user[name/text()='" + velvetCascadeUser
                    + "' and pass/text()='" + velvetCascadePass + "']" + "/secret/text()";
            String velvetCascadeSecret = (String) velvetCascadeXPath.evaluate(velvetCascadeQuery, velvetCascadeXml, XPathConstants.STRING);
            System.out.println(velvetCascadeSecret);
        }
    }
}
